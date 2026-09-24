#!/usr/bin/env python
"""
network_trackers.py — network observability trackers for ebpf_monitor.py

Drop-in module. Import these classes into ebpf_monitor.py and register them
the same way GCPauseTracker / HandoffTracker are registered.

Trackers:
  TcpAcceptTracker    metric "tcp_accept"       -> ClickHouse ebpf_tcp_accept
  TcpConnectTracker   metric "tcp_connect"      -> ClickHouse ebpf_tcp_connect
  TcpLossTracker      metric "tcp_loss"         -> ClickHouse ebpf_tcp_loss
  HostNetHealthTracker metric "host_net_health" -> ClickHouse ebpf_host_net_health

Design notes
------------
* Each tracker emits event dicts whose keys EXACTLY match the ClickHouse
  table columns (EventWriter inserts every key except "metric" as a column).
  IP:port strings are split into *_ip / *_port here, and the identity
  columns (server_name, machine_ip, published_date) are added here.
* The network probes do NOT use BaseTracker.pid_filter_clause() — loss
  events fire in softirq with no meaningful PID, and accept/connect are
  captured box-wide. There is no FILTER_PID token in this BPF.
* TcpAcceptTracker / TcpConnectTracker / TcpLossTracker are perf-buffer
  trackers and plug straight into the existing main poll loop.
* HostNetHealthTracker has NO BPF and NO perf buffer (perf_buffer_name()
  returns None). It runs a periodic userspace thread, exactly like
  HandoffTracker's periodic emitter. main() must call its
  start_periodic_emitter() after setup(), and stop() on shutdown.

These trackers reuse BaseTracker only for __init__ / emit / writer plumbing.
They override bpf_text/attach_probes/handle_event with their own logic and
build their own docs (NOT base_doc(), which is GC-pause shaped).
"""
from __future__ import print_function

import json
import os
import socket
import struct
import subprocess
import sys
import threading
import time
from collections import Counter
from datetime import datetime, timezone

from bcc import BPF


# =============================================================================
# Local helpers (self-contained so this module has no ordering dependency on
# ebpf_monitor.py beyond importing BaseTracker)
# =============================================================================

_BOOT_TO_WALL_OFFSET = time.time() - time.monotonic()


def _ktime_to_iso(ktime_ns):
    if not ktime_ns:
        return None
    wall_seconds = (ktime_ns / 1e9) + _BOOT_TO_WALL_OFFSET
    return datetime.fromtimestamp(wall_seconds, tz=timezone.utc).strftime(
        "%Y-%m-%d %H:%M:%S.%f")


def _now_iso():
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S.%f")


def _decode_comm(comm_bytes):
    try:
        return bytes(comm_bytes).split(b'\x00', 1)[0].decode(
            'utf-8', errors='replace')
    except Exception:
        return ""


def _ipv4_to_str(addr_be32):
    return socket.inet_ntoa(struct.pack("=I", addr_be32))


# =============================================================================
# Step 2 + Step 3 MERGED -> TcpHandshakeTracker
#   metric "tcp_accept"  -> ebpf_tcp_accept    (inbound  connections)
#   metric "tcp_connect" -> ebpf_tcp_connect   (outbound connections)
#
# WHY MERGED:
#   Both inbound (accept) and outbound (connect) tracking need a kprobe on
#   tcp_set_state. On kernel 4.14, attaching TWO kprobes to the SAME kernel
#   function from TWO separate BPF programs fails with EBUSY ("Device or
#   resource busy"). So accept + connect are merged into ONE BPF program with
#   ONE tcp_set_state kprobe that handles BOTH transitions:
#       SYN_RECV  -> ESTABLISHED   = inbound  handshake done   (accept path)
#       SYN_SENT  -> ESTABLISHED   = outbound connect success  (connect path)
#       SYN_SENT  -> CLOSE         = outbound connect failure  (connect path)
#
#   It still emits to the TWO separate ClickHouse tables, unchanged:
#       inbound  events -> metric "tcp_accept"  -> ebpf_tcp_accept
#       outbound events -> metric "tcp_connect" -> ebpf_tcp_connect
#
# This tracker has TWO perf buffers (accept_events, connect_events). The main
# poll loop only polls one buffer per tracker via perf_buffer_name(), so this
# class overrides poll handling: see poll() / and note in INTEGRATION below.
# =============================================================================

class TcpHandshakeTracker(object):
    """Merged inbound-accept + outbound-connect tracker. One BPF program,
    one tcp_set_state kprobe, two perf buffers, two ClickHouse tables."""
    METRIC_NAME = "tcp_handshake"          # tracker id; events use tcp_accept/tcp_connect

    OUTCOME_NAMES = {1: "success", 2: "failure"}

    BPF_TEXT = r"""
    #include <uapi/linux/ptrace.h>
    #include <net/sock.h>
    #include <net/inet_sock.h>
    #include <net/inet_connection_sock.h>
    #include <net/tcp_states.h>
    #include <linux/tcp.h>

    // ---- inbound (accept) state ------------------------------------------
    BPF_HASH(listen_sk_by_tid, u32, struct sock *);
    BPF_TABLE("lru_hash", struct sock *, u64, established_ts, 65536);

    // ---- outbound (connect) state ----------------------------------------
    struct connect_info_t {
        u64  connect_start_ns;
        u32  pid;
        u32  tid;
        char comm[16];
    };
    BPF_TABLE("lru_hash", struct sock *, struct connect_info_t,
              connect_starts, 65536);

    // ---- inbound event ----------------------------------------------------
    struct accept_event_t {
        u64  ts_ns;
        u32  pid;
        u32  tid;
        u16  family;
        u32  peer_addr;
        u32  local_addr;
        u16  peer_port;
        u16  local_port;
        u32  syn_queue_len;
        u32  accept_queue_len;
        u32  accept_queue_max;
        u64  accept_dwell_us;
        u32  handshake_rtt_us;
        u8   had_dwell_data;
        char comm[16];
    };
    BPF_PERF_OUTPUT(accept_events);

    // ---- outbound event ---------------------------------------------------
    struct connect_event_t {
        u64  ts_ns;
        u32  pid;
        u32  tid;
        u16  family;
        u32  dst_addr;
        u32  src_addr;
        u16  dst_port;
        u16  src_port;
        u64  handshake_us;
        u32  srtt_us;
        u8   outcome;          // 1 = success, 2 = failure
        char comm[16];
    };
    BPF_PERF_OUTPUT(connect_events);

    // =====================================================================
    // SINGLE tcp_set_state kprobe — handles BOTH inbound and outbound.
    // =====================================================================
    int trace_hs_set_state(struct pt_regs *ctx)
    {
        struct sock *sk = (struct sock *)PT_REGS_PARM1(ctx);
        int new_state   = (int)PT_REGS_PARM2(ctx);

        u8 old_state = 0;
        bpf_probe_read_kernel(&old_state, sizeof(old_state),
                              &sk->__sk_common.skc_state);

        // ---- INBOUND: SYN_RECV -> ESTABLISHED ----------------------------
        if (old_state == TCP_SYN_RECV && new_state == TCP_ESTABLISHED) {
            u64 ts = bpf_ktime_get_ns();
            established_ts.update(&sk, &ts);
            return 0;
        }

        // ---- OUTBOUND: SYN_SENT -> ESTABLISHED / CLOSE -------------------
        if (old_state == TCP_SYN_SENT &&
            (new_state == TCP_ESTABLISHED || new_state == TCP_CLOSE)) {

            struct connect_info_t *info = connect_starts.lookup(&sk);
            if (info == NULL) return 0;   // not one of ours

            u16 family = 0;
            bpf_probe_read_kernel(&family, sizeof(family),
                                  &sk->__sk_common.skc_family);
            if (family != AF_INET) {
                connect_starts.delete(&sk);
                return 0;
            }

            u64 now = bpf_ktime_get_ns();
            struct connect_event_t evt = {};
            evt.ts_ns        = now;
            evt.pid          = info->pid;
            evt.tid          = info->tid;
            evt.family       = family;
            evt.handshake_us = (now - info->connect_start_ns) / 1000;
            __builtin_memcpy(&evt.comm, info->comm, sizeof(evt.comm));

            bpf_probe_read_kernel(&evt.dst_addr, sizeof(evt.dst_addr),
                                  &sk->__sk_common.skc_daddr);
            bpf_probe_read_kernel(&evt.src_addr, sizeof(evt.src_addr),
                                  &sk->__sk_common.skc_rcv_saddr);
            u16 dport_be = 0;
            bpf_probe_read_kernel(&dport_be, sizeof(dport_be),
                                  &sk->__sk_common.skc_dport);
            evt.dst_port = ntohs(dport_be);
            bpf_probe_read_kernel(&evt.src_port, sizeof(evt.src_port),
                                  &sk->__sk_common.skc_num);

            if (new_state == TCP_ESTABLISHED) {
                evt.outcome = 1;
                struct tcp_sock *tp = (struct tcp_sock *)sk;
                u32 srtt_us = 0;
                bpf_probe_read_kernel(&srtt_us, sizeof(srtt_us),
                                      &tp->srtt_us);
                evt.srtt_us = srtt_us >> 3;
            } else {
                evt.outcome = 2;
                evt.srtt_us = 0;
            }

            connect_events.perf_submit(ctx, &evt, sizeof(evt));
            connect_starts.delete(&sk);
            return 0;
        }

        return 0;
    }

    // =====================================================================
    // INBOUND: inet_csk_accept entry + return
    // =====================================================================
    int trace_accept_entry(struct pt_regs *ctx, struct sock *listen_sk)
    {
        u32 tid = (u32)bpf_get_current_pid_tgid();
        listen_sk_by_tid.update(&tid, &listen_sk);
        return 0;
    }

    int trace_accept_return(struct pt_regs *ctx)
    {
        u32 pid = bpf_get_current_pid_tgid() >> 32;
        u32 tid = (u32)bpf_get_current_pid_tgid();

        struct sock **listen_skp = listen_sk_by_tid.lookup(&tid);
        if (listen_skp == NULL) return 0;
        struct sock *listen_sk = *listen_skp;
        listen_sk_by_tid.delete(&tid);

        struct sock *new_sk = (struct sock *)PT_REGS_RC(ctx);
        if (new_sk == NULL) return 0;

        u16 family = 0;
        bpf_probe_read_kernel(&family, sizeof(family),
                              &new_sk->__sk_common.skc_family);
        if (family != AF_INET) return 0;

        struct accept_event_t evt = {};
        u64 now = bpf_ktime_get_ns();
        evt.ts_ns  = now;
        evt.pid    = pid;
        evt.tid    = tid;
        evt.family = family;
        bpf_get_current_comm(&evt.comm, sizeof(evt.comm));

        bpf_probe_read_kernel(&evt.peer_addr,  sizeof(evt.peer_addr),
                              &new_sk->__sk_common.skc_daddr);
        bpf_probe_read_kernel(&evt.local_addr, sizeof(evt.local_addr),
                              &new_sk->__sk_common.skc_rcv_saddr);
        u16 peer_port_be = 0;
        bpf_probe_read_kernel(&peer_port_be, sizeof(peer_port_be),
                              &new_sk->__sk_common.skc_dport);
        evt.peer_port  = ntohs(peer_port_be);
        bpf_probe_read_kernel(&evt.local_port, sizeof(evt.local_port),
                              &new_sk->__sk_common.skc_num);

        struct inet_connection_sock *l_icsk = inet_csk(listen_sk);
        bpf_probe_read_kernel(&evt.syn_queue_len, sizeof(evt.syn_queue_len),
                              &l_icsk->icsk_accept_queue.qlen);
        bpf_probe_read_kernel(&evt.accept_queue_len,
                              sizeof(evt.accept_queue_len),
                              &listen_sk->sk_ack_backlog);
        bpf_probe_read_kernel(&evt.accept_queue_max,
                              sizeof(evt.accept_queue_max),
                              &listen_sk->sk_max_ack_backlog);

        u64 *est_ts = established_ts.lookup(&new_sk);
        if (est_ts != NULL) {
            evt.accept_dwell_us  = (now - *est_ts) / 1000;
            evt.had_dwell_data   = 1;
            established_ts.delete(&new_sk);
        }

        struct tcp_sock *tp = (struct tcp_sock *)new_sk;
        u32 srtt_us = 0;
        bpf_probe_read_kernel(&srtt_us, sizeof(srtt_us), &tp->srtt_us);
        evt.handshake_rtt_us = srtt_us >> 3;

        accept_events.perf_submit(ctx, &evt, sizeof(evt));
        return 0;
    }

    // =====================================================================
    // OUTBOUND: tcp_v4_connect entry (process context — capture T0 + pid)
    // =====================================================================
    int trace_connect_entry(struct pt_regs *ctx, struct sock *sk)
    {
        u32 pid = bpf_get_current_pid_tgid() >> 32;
        u32 tid = (u32)bpf_get_current_pid_tgid();

        struct connect_info_t info = {};
        info.connect_start_ns = bpf_ktime_get_ns();
        info.pid = pid;
        info.tid = tid;
        bpf_get_current_comm(&info.comm, sizeof(info.comm));

        connect_starts.update(&sk, &info);
        return 0;
    }
    """

    def __init__(self, pids, env_name, machine_ip, resolver, comm_cache,
                 writer=None, also_stdout=False):
        self.env_name = env_name
        self.machine_ip = machine_ip
        self.writer = writer
        self.also_stdout = also_stdout
        self.bpf = None

    # This tracker has TWO perf buffers. perf_buffer_name() is kept for
    # interface compatibility but the main loop's single-buffer poll is NOT
    # enough — see poll() below and the INTEGRATION note.
    def perf_buffer_name(self):
        return "accept_events"

    def setup(self):
        self.bpf = BPF(text=self.BPF_TEXT)
        # ONE kprobe on tcp_set_state — no collision.
        self.bpf.attach_kprobe(event="tcp_set_state",
                               fn_name="trace_hs_set_state")
        # inbound
        self.bpf.attach_kprobe(event="inet_csk_accept",
                               fn_name="trace_accept_entry")
        self.bpf.attach_kretprobe(event="inet_csk_accept",
                                  fn_name="trace_accept_return")
        # outbound
        self.bpf.attach_kprobe(event="tcp_v4_connect",
                               fn_name="trace_connect_entry")
        # open BOTH perf buffers
        self.bpf["accept_events"].open_perf_buffer(
            self._safe_handle_accept, page_cnt=64)
        self.bpf["connect_events"].open_perf_buffer(
            self._safe_handle_connect, page_cnt=64)
        print("[{}] tracker initialized (inbound+outbound, "
              "one tcp_set_state hook)".format(self.METRIC_NAME),
              file=sys.stderr)

    def poll(self, timeout=100):
        """Poll BOTH perf buffers. The main loop must call tracker.poll()
        for this tracker (see INTEGRATION note) because perf_buffer_poll on
        the BPF object drains all open buffers in one call."""
        if self.bpf is not None:
            self.bpf.perf_buffer_poll(timeout=timeout)

    # ---- inbound handler --------------------------------------------------
    def _safe_handle_accept(self, cpu, data, size):
        try:
            self._handle_accept(cpu, data, size)
        except Exception as ex:
            print("[tcp_accept] handler error: {}".format(ex),
                  file=sys.stderr)

    def _handle_accept(self, cpu, data, size):
        e = self.bpf["accept_events"].event(data)
        doc = {
            "metric":           "tcp_accept",
            "server_name":      self.env_name,
            "machine_ip":       self.machine_ip,
            "event_time":       _ktime_to_iso(e.ts_ns),
            "pid":              e.pid,
            "tid":              e.tid,
            "comm":             _decode_comm(e.comm),
            "family":           "AF_INET" if e.family == socket.AF_INET
                                 else str(e.family),
            "peer_ip":          _ipv4_to_str(e.peer_addr),
            "peer_port":        e.peer_port,
            "local_ip":         _ipv4_to_str(e.local_addr),
            "local_port":       e.local_port,
            "syn_queue_len":    e.syn_queue_len,
            "accept_queue_len": e.accept_queue_len,
            "accept_queue_max": e.accept_queue_max,
            "accept_dwell_us":  e.accept_dwell_us if e.had_dwell_data else 0,
            "handshake_rtt_us": e.handshake_rtt_us,
            "published_date":   _now_iso(),
        }
        _emit(self, doc)

    # ---- outbound handler -------------------------------------------------
    def _safe_handle_connect(self, cpu, data, size):
        try:
            self._handle_connect(cpu, data, size)
        except Exception as ex:
            print("[tcp_connect] handler error: {}".format(ex),
                  file=sys.stderr)

    def _handle_connect(self, cpu, data, size):
        e = self.bpf["connect_events"].event(data)
        doc = {
            "metric":        "tcp_connect",
            "server_name":   self.env_name,
            "machine_ip":    self.machine_ip,
            "event_time":    _ktime_to_iso(e.ts_ns),
            "pid":           e.pid,
            "tid":           e.tid,
            "comm":          _decode_comm(e.comm),
            "family":        "AF_INET" if e.family == socket.AF_INET
                             else str(e.family),
            "src_ip":        _ipv4_to_str(e.src_addr),
            "src_port":      e.src_port,
            "dst_ip":        _ipv4_to_str(e.dst_addr),
            "dst_port":      e.dst_port,
            "handshake_us":  e.handshake_us,
            "srtt_us":       e.srtt_us if e.outcome == 1 else 0,
            "outcome":       self.OUTCOME_NAMES.get(e.outcome, "unknown"),
            "published_date": _now_iso(),
        }
        _emit(self, doc)



# =============================================================================
# Step 4 -> TcpLossTracker   (metric: tcp_loss -> ebpf_tcp_loss)
# =============================================================================

class TcpLossTracker(object):
    """TCP loss / reliability probe (step4): retransmit, recovery, loss,
    send_rst, recv_rst, zero_window — with window + cwnd context."""
    METRIC_NAME = "tcp_loss"

    BPF_TEXT = r"""
    #include <uapi/linux/ptrace.h>
    #include <net/sock.h>
    #include <net/inet_sock.h>
    #include <linux/tcp.h>

    #define EVT_RETRANSMIT  1
    #define EVT_RECOVERY    2
    #define EVT_LOSS        3
    #define EVT_SEND_RST    4
    #define EVT_RECV_RST    5
    #define EVT_ZERO_WINDOW 6

    struct loss_event_t {
        u64  ts_ns;
        u8   event_type;
        u16  family;
        u32  src_addr;
        u32  dst_addr;
        u16  src_port;
        u16  dst_port;
        u32  srtt_us;
        u32  snd_cwnd;
        u32  total_retrans;
        u32  lost_out;
        u32  snd_wnd;
        u32  rcv_wnd;
        u8   tcp_state;
        char comm[16];
    };

    BPF_PERF_OUTPUT(loss_events);

    static __always_inline int emit_loss_event(void *ctx, struct sock *sk,
                                               u8 evt_type)
    {
        if (sk == NULL) return 0;

        u16 family = 0;
        bpf_probe_read_kernel(&family, sizeof(family),
                              &sk->__sk_common.skc_family);
        if (family != AF_INET) return 0;

        struct loss_event_t evt = {};
        evt.ts_ns       = bpf_ktime_get_ns();
        evt.event_type  = evt_type;
        evt.family      = family;

        bpf_probe_read_kernel(&evt.dst_addr, sizeof(evt.dst_addr),
                              &sk->__sk_common.skc_daddr);
        bpf_probe_read_kernel(&evt.src_addr, sizeof(evt.src_addr),
                              &sk->__sk_common.skc_rcv_saddr);
        u16 dport_be = 0;
        bpf_probe_read_kernel(&dport_be, sizeof(dport_be),
                              &sk->__sk_common.skc_dport);
        evt.dst_port = ntohs(dport_be);
        bpf_probe_read_kernel(&evt.src_port, sizeof(evt.src_port),
                              &sk->__sk_common.skc_num);
        bpf_probe_read_kernel(&evt.tcp_state, sizeof(evt.tcp_state),
                              &sk->__sk_common.skc_state);

        struct tcp_sock *tp = (struct tcp_sock *)sk;
        u32 srtt_us = 0, snd_cwnd = 0, total_retrans = 0, lost_out = 0;
        u32 snd_wnd = 0, rcv_wnd = 0;
        bpf_probe_read_kernel(&srtt_us,       sizeof(srtt_us),       &tp->srtt_us);
        bpf_probe_read_kernel(&snd_cwnd,      sizeof(snd_cwnd),      &tp->snd_cwnd);
        bpf_probe_read_kernel(&total_retrans, sizeof(total_retrans), &tp->total_retrans);
        bpf_probe_read_kernel(&lost_out,      sizeof(lost_out),      &tp->lost_out);
        bpf_probe_read_kernel(&snd_wnd,       sizeof(snd_wnd),       &tp->snd_wnd);
        bpf_probe_read_kernel(&rcv_wnd,       sizeof(rcv_wnd),       &tp->rcv_wnd);
        evt.srtt_us       = srtt_us >> 3;
        evt.snd_cwnd      = snd_cwnd;
        evt.total_retrans = total_retrans;
        evt.lost_out      = lost_out;
        evt.snd_wnd       = snd_wnd;
        evt.rcv_wnd       = rcv_wnd;

        bpf_get_current_comm(&evt.comm, sizeof(evt.comm));

        loss_events.perf_submit(ctx, &evt, sizeof(evt));
        return 0;
    }

    int trace_retransmit(struct pt_regs *ctx, struct sock *sk)
    { return emit_loss_event(ctx, sk, EVT_RETRANSMIT); }

    int trace_enter_recovery(struct pt_regs *ctx, struct sock *sk)
    { return emit_loss_event(ctx, sk, EVT_RECOVERY); }

    int trace_enter_loss(struct pt_regs *ctx, struct sock *sk)
    { return emit_loss_event(ctx, sk, EVT_LOSS); }

    int trace_send_reset(struct pt_regs *ctx, struct sock *sk)
    { return emit_loss_event(ctx, sk, EVT_SEND_RST); }

    int trace_recv_reset(struct pt_regs *ctx, struct sock *sk)
    { return emit_loss_event(ctx, sk, EVT_RECV_RST); }

    int trace_send_probe0(struct pt_regs *ctx, struct sock *sk)
    { return emit_loss_event(ctx, sk, EVT_ZERO_WINDOW); }
    """

    EVENT_NAMES = {
        1: "retransmit", 2: "recovery", 3: "loss",
        4: "send_rst", 5: "recv_rst", 6: "zero_window",
    }
    TCP_STATE_NAMES = {
        1: "ESTABLISHED", 2: "SYN_SENT", 3: "SYN_RECV", 4: "FIN_WAIT1",
        5: "FIN_WAIT2", 6: "TIME_WAIT", 7: "CLOSE", 8: "CLOSE_WAIT",
        9: "LAST_ACK", 10: "LISTEN", 11: "CLOSING", 12: "NEW_SYN_RECV",
    }
    PROBES = [
        ("tcp_retransmit_skb",    "trace_retransmit"),
        ("tcp_enter_recovery",    "trace_enter_recovery"),
        ("tcp_enter_loss",        "trace_enter_loss"),
        ("tcp_send_active_reset", "trace_send_reset"),
        ("tcp_reset",             "trace_recv_reset"),
        ("tcp_send_probe0",       "trace_send_probe0"),
    ]

    def __init__(self, pids, env_name, machine_ip, resolver, comm_cache,
                 writer=None, also_stdout=False, filter_ip=None):
        self.env_name = env_name
        self.machine_ip = machine_ip
        self.writer = writer
        self.also_stdout = also_stdout
        self.filter_ip = filter_ip
        self.bpf = None

    def perf_buffer_name(self):
        return "loss_events"

    def setup(self):
        self.bpf = BPF(text=self.BPF_TEXT)
        attached = []
        for kprobe_name, fn_name in self.PROBES:
            try:
                self.bpf.attach_kprobe(event=kprobe_name, fn_name=fn_name)
                attached.append(kprobe_name)
            except Exception as ex:
                print("[{}] WARN: could not attach to {}: {}".format(
                    self.METRIC_NAME, kprobe_name, ex), file=sys.stderr)
        self.bpf[self.perf_buffer_name()].open_perf_buffer(
            self._safe_handle_event, page_cnt=64)
        print("[{}] tracker initialized (attached: {})".format(
            self.METRIC_NAME, ", ".join(attached)), file=sys.stderr)

    def _safe_handle_event(self, cpu, data, size):
        try:
            self.handle_event(cpu, data, size)
        except Exception as ex:
            print("[{}] handler error: {}".format(self.METRIC_NAME, ex),
                  file=sys.stderr)

    def handle_event(self, cpu, data, size):
        e = self.bpf["loss_events"].event(data)
        src = _ipv4_to_str(e.src_addr)
        dst = _ipv4_to_str(e.dst_addr)

        if self.filter_ip and self.filter_ip not in (src, dst):
            return

        state = int(e.tcp_state)
        doc = {
            "metric":        self.METRIC_NAME,
            "server_name":   self.env_name,
            "machine_ip":    self.machine_ip,
            "event_time":    _ktime_to_iso(e.ts_ns),
            "event":         self.EVENT_NAMES.get(e.event_type, "unknown"),
            "comm":          _decode_comm(e.comm),
            "src_ip":        src,
            "src_port":      e.src_port,
            "dst_ip":        dst,
            "dst_port":      e.dst_port,
            "tcp_state":     self.TCP_STATE_NAMES.get(
                                 state, "STATE_{}".format(state)),
            "srtt_us":       e.srtt_us,
            "snd_cwnd":      e.snd_cwnd,
            "total_retrans": e.total_retrans,
            "lost_out":      e.lost_out,
            "snd_wnd":       e.snd_wnd,
            "rcv_wnd":       e.rcv_wnd,
            "published_date": _now_iso(),
        }
        _emit(self, doc)


# =============================================================================
# host_net_health -> HostNetHealthTracker
#   (metric: host_net_health -> ebpf_host_net_health)
#
# NO BPF, NO perf buffer. Runs a periodic userspace thread, like
# HandoffTracker's periodic emitter. perf_buffer_name() returns None so the
# main poll loop skips it.
# =============================================================================

# thresholds for the warnings[] array
_WARN_CLOSE_WAIT        = 100
_WARN_TIME_WAIT_PER_DST = 15000
_WARN_SYN_SENT          = 30
_WARN_SYN_RECV          = 100
_WARN_FD_UTIL_PCT       = 80.0
_WARN_PORT_UTIL_PCT     = 60.0

_AWS_COUNTERS = [
    "bw_in_allowance_exceeded",
    "bw_out_allowance_exceeded",
    "pps_allowance_exceeded",
    "conntrack_allowance_exceeded",
    "linklocal_allowance_exceeded",
]
_AWS_GAUGE = "conntrack_allowance_available"


class HostNetHealthTracker(object):
    """Userspace host network health poller. Emits one host_net_health doc
    per interval, flattened to match the ebpf_host_net_health columns."""
    METRIC_NAME = "host_net_health"

    def __init__(self, pids, env_name, machine_ip, resolver, comm_cache,
                 writer=None, also_stdout=False,
                 interface=None, interval=10, procs="nginx,gunicorn"):
        self.env_name = env_name
        self.machine_ip = machine_ip
        self.writer = writer
        self.also_stdout = also_stdout
        self.bpf = None                      # no BPF
        self.interval = interval
        self.proc_names = [p.strip() for p in procs.split(",") if p.strip()]
        self.interface = interface or self._detect_iface()
        self.port_range = self._read_port_range()
        self._prev_aws = {}
        self._stop_emitter = False
        self._emitter_thread = None

    # ---- duck-typed interface the main loop expects -----------------------
    def perf_buffer_name(self):
        return None                          # -> main loop skips polling it

    def setup(self):
        # No BPF to compile. Prime the AWS counter baseline.
        self._prev_aws = self._read_ethtool()
        print("[{}] tracker initialized (interface={}, interval={}s)".format(
            self.METRIC_NAME, self.interface, self.interval), file=sys.stderr)

    # ---- periodic emitter (same pattern as HandoffTracker) ----------------
    def start_periodic_emitter(self):
        self._emitter_thread = threading.Thread(
            target=self._emitter_loop, daemon=True)
        self._emitter_thread.start()
        print("[{}] periodic emitter started (every {}s)".format(
            self.METRIC_NAME, self.interval), file=sys.stderr)

    def stop(self):
        self._stop_emitter = True

    def _emitter_loop(self):
        time.sleep(0.5)
        while not self._stop_emitter:
            try:
                doc = self._build_snapshot()
                _emit(self, doc)
            except Exception as ex:
                print("[{}] emitter error: {}".format(self.METRIC_NAME, ex),
                      file=sys.stderr)
            time.sleep(self.interval)

    # ---- collectors -------------------------------------------------------
    @staticmethod
    def _detect_iface():
        for cand in ("ens5", "eth0", "ens6"):
            if os.path.exists("/sys/class/net/{}".format(cand)):
                return cand
        for entry in os.listdir("/sys/class/net"):
            if entry != "lo":
                return entry
        return "eth0"

    @staticmethod
    def _read_port_range():
        try:
            with open("/proc/sys/net/ipv4/ip_local_port_range") as f:
                lo, hi = f.read().split()
                return int(lo), int(hi)
        except Exception:
            return 32768, 60999

    def _read_ethtool(self):
        try:
            out = subprocess.check_output(
                ["ethtool", "-S", self.interface],
                stderr=subprocess.DEVNULL).decode("utf-8")
        except Exception:
            return {}
        vals = {}
        for line in out.splitlines():
            line = line.strip()
            if ":" not in line:
                continue
            key, _, val = line.partition(":")
            key = key.strip()
            val = val.strip()
            if key in _AWS_COUNTERS or key == _AWS_GAUGE:
                try:
                    vals[key] = int(val)
                except ValueError:
                    pass
        return vals

    @staticmethod
    def _split_host_port(addr):
        if addr.startswith("["):
            host, _, port = addr.rpartition("]:")
            return host.lstrip("["), port
        host, _, port = addr.rpartition(":")
        return host, port

    def _read_ss(self):
        out = subprocess.check_output(
            ["ss", "-tan"], stderr=subprocess.DEVNULL).decode("utf-8")
        listening_ports = set()
        rows = []
        for line in out.splitlines()[1:]:
            parts = line.split()
            if len(parts) < 5:
                continue
            state = parts[0]
            lhost, lport = self._split_host_port(parts[3])
            phost, pport = self._split_host_port(parts[4])
            rows.append((state, lhost, lport, phost, pport))
            if state == "LISTEN":
                listening_ports.add(lport)

        state_counts = Counter()
        est_in = est_out = 0
        tw_by_dst = Counter()
        for state, lhost, lport, phost, pport in rows:
            state_counts[state] += 1
            if state == "ESTAB":
                if lport in listening_ports:
                    est_in += 1
                else:
                    est_out += 1
            if state == "TIME-WAIT":
                tw_by_dst[phost] += 1
        return {
            "state_counts": dict(state_counts),
            "established_inbound": est_in,
            "established_outbound": est_out,
            "time_wait_by_dst": tw_by_dst,
        }

    @staticmethod
    def _find_pids_by_comm(names):
        result = {n: [] for n in names}
        for entry in os.listdir("/proc"):
            if not entry.isdigit():
                continue
            try:
                with open("/proc/{}/comm".format(entry)) as f:
                    comm = f.read().strip()
            except Exception:
                continue
            for n in names:
                if comm == n[:15]:
                    result[n].append(int(entry))
        return result

    @staticmethod
    def _fd_count(pid):
        try:
            return len(os.listdir("/proc/{}/fd".format(pid)))
        except Exception:
            return 0

    @staticmethod
    def _fd_limit(pid):
        try:
            with open("/proc/{}/limits".format(pid)) as f:
                for line in f:
                    if line.startswith("Max open files"):
                        for tok in line.split():
                            if tok.isdigit():
                                return int(tok)
        except Exception:
            pass
        return -1

    def _collect_fd_usage(self):
        out = []
        pid_map = self._find_pids_by_comm(self.proc_names)
        for name, pids in pid_map.items():
            if not pids:
                out.append({"proc": name, "pids": 0, "fd_count": 0,
                            "fd_limit": -1, "fd_util_pct": 0.0})
                continue
            total_fds = sum(self._fd_count(p) for p in pids)
            limits = [self._fd_limit(p) for p in pids]
            limits = [l for l in limits if l > 0]
            lim = min(limits) if limits else -1
            util = round(100.0 * total_fds / lim, 2) if lim > 0 else 0.0
            out.append({"proc": name, "pids": len(pids),
                        "fd_count": total_fds, "fd_limit": lim,
                        "fd_util_pct": util})
        return out

    # ---- snapshot assembly (FLATTENED to match the table columns) ---------
    def _build_snapshot(self):
        ss_data = self._read_ss()
        curr_aws = self._read_ethtool()
        aws_deltas = {c: curr_aws.get(c, 0) - self._prev_aws.get(c, 0)
                      for c in _AWS_COUNTERS}
        aws_totals = {c: curr_aws.get(c, 0) for c in _AWS_COUNTERS}
        aws_gauge = curr_aws.get(_AWS_GAUGE, -1)
        if curr_aws:
            self._prev_aws = curr_aws
        fd_usage = self._collect_fd_usage() if self.proc_names else []

        sc = ss_data["state_counts"]
        time_wait = sc.get("TIME-WAIT", 0)
        close_wait = sc.get("CLOSE-WAIT", 0)
        syn_sent = sc.get("SYN-SENT", 0)
        syn_recv = sc.get("SYN-RECV", 0)
        fin_wait = sc.get("FIN-WAIT-1", 0) + sc.get("FIN-WAIT-2", 0)
        last_ack = sc.get("LAST-ACK", 0)
        closing = sc.get("CLOSING", 0)

        tw_by_dst = ss_data["time_wait_by_dst"]
        top_tw = sorted(tw_by_dst.items(), key=lambda kv: kv[1],
                        reverse=True)[:5]
        top_tw_list = [{"dst": d, "count": c} for d, c in top_tw]
        max_tw_single = top_tw[0][1] if top_tw else 0

        lo, hi = self.port_range
        range_size = hi - lo + 1
        port_util = (round(100.0 * max_tw_single / range_size, 2)
                     if range_size else 0.0)

        warnings = []
        if close_wait > _WARN_CLOSE_WAIT:
            warnings.append(
                "close_wait={} (possible fd leak)".format(close_wait))
        if max_tw_single > _WARN_TIME_WAIT_PER_DST:
            warnings.append("time_wait to {} = {} (port-exhaustion risk)"
                            .format(top_tw[0][0], max_tw_single))
        if port_util > _WARN_PORT_UTIL_PCT:
            warnings.append(
                "ephemeral port utilization {}% to single dst".format(
                    port_util))
        if syn_sent > _WARN_SYN_SENT:
            warnings.append(
                "syn_sent={} (outbound handshakes struggling)".format(
                    syn_sent))
        if syn_recv > _WARN_SYN_RECV:
            warnings.append(
                "syn_recv={} (inbound handshakes struggling)".format(
                    syn_recv))
        for fd in fd_usage:
            if fd["fd_util_pct"] > _WARN_FD_UTIL_PCT:
                warnings.append("{} fd usage {}% ({}/{})".format(
                    fd["proc"], fd["fd_util_pct"],
                    fd["fd_count"], fd["fd_limit"]))
        if any(aws_deltas.get(c, 0) > 0 for c in _AWS_COUNTERS):
            warnings.append("aws throttling active this interval")

        # FLAT doc — keys match default.ebpf_host_net_health columns
        doc = {
            "metric":               self.METRIC_NAME,
            "server_name":          self.env_name,
            "machine_ip":           self.machine_ip,
            "event_time":           _now_iso(),
            "interface":            self.interface,
            "interval_s":           self.interval,
            "established_inbound":  ss_data["established_inbound"],
            "established_outbound": ss_data["established_outbound"],
            "time_wait":            time_wait,
            "close_wait":           close_wait,
            "syn_sent":             syn_sent,
            "syn_recv":             syn_recv,
            "fin_wait":             fin_wait,
            "last_ack":             last_ack,
            "closing":              closing,
            "max_time_wait_one_dst": max_tw_single,
            "port_util_pct":        port_util,
            "delta_bw_in":     aws_deltas.get("bw_in_allowance_exceeded", 0),
            "delta_bw_out":    aws_deltas.get("bw_out_allowance_exceeded", 0),
            "delta_pps":       aws_deltas.get("pps_allowance_exceeded", 0),
            "delta_conntrack": aws_deltas.get("conntrack_allowance_exceeded", 0),
            "delta_linklocal": aws_deltas.get("linklocal_allowance_exceeded", 0),
            "conntrack_available": aws_gauge,
            "total_bw_in":  aws_totals.get("bw_in_allowance_exceeded", 0),
            "total_bw_out": aws_totals.get("bw_out_allowance_exceeded", 0),
            "total_pps":    aws_totals.get("pps_allowance_exceeded", 0),
            # nested detail kept as JSON strings (String columns)
            "time_wait_top_dst_json": json.dumps(top_tw_list),
            "fd_usage_json":          json.dumps(fd_usage),
            "warnings":               warnings,
            "published_date":         _now_iso(),
        }
        return doc


# =============================================================================
# Shared emit helper — same behavior as BaseTracker.emit()
# =============================================================================

def _emit(tracker, doc):
    if tracker.writer is not None:
        try:
            tracker.writer.enqueue(doc)
        except Exception as ex:
            print("[{}] enqueue error: {}".format(tracker.METRIC_NAME, ex),
                  file=sys.stderr)
    if tracker.also_stdout or tracker.writer is None:
        try:
            print(json.dumps(doc))
            sys.stdout.flush()
        except Exception as ex:
            print("[{}] stdout error: {}".format(tracker.METRIC_NAME, ex),
                  file=sys.stderr)