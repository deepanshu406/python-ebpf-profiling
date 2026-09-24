#!/usr/bin/env python
"""
Combined eBPF monitor with ClickHouse + Elasticsearch ingestion.

NEW in this version:
  - Each event now includes container_pid and container_tid alongside host pid/tid.
    This enables JOIN with OTel spans (which carry container-view IDs).
  - ThreadNameResolver maintains a host->container ID map, refreshed every 30s
    via /proc/<host_pid>/status NSpid lines (zero cost on event hot path).

Trackers:
  - GCPauseTracker        (metric: "gc_pause"  -> ClickHouse table: ebpf_gc_pause)
  - GILWaitTracker        (metric: "gil_wait"  -> ClickHouse table: ebpf_gil_wait)
  - OffCPUStackTracker    (metric: "off_cpu"   -> ClickHouse table: ebpf_off_cpu)
  - HandoffTracker        (metric: "handoff"   -> ClickHouse table: ebpf_handoff)
                          [+ periodic ES: queue-size, request-count, thread-pool-utilisation]
  - MutexLockTracker      (counter polled by HandoffTracker periodic emitter)
  - PyStackProfilerTracker (metric: "py_stack" -> ClickHouse table: ebpf_py_stacks)

Usage:
  sudo python3 ebpf_monitor.py \\
    -p <PID1> <PID2> \\
    -e my-env \\
    --also-stdout

  With ClickHouse + Elasticsearch:
  sudo python3 ebpf_monitor.py \\
    -p <PID1> <PID2> \\
    -e my-env \\
    --clickhouse-url http://localhost:8123 \\
    --es-url https://localhost:9200 \\
    --es-user elastic \\
    --es-password '<password>'
"""
from __future__ import print_function

import argparse
import ctypes
import json
import os
import queue
import socket
import ssl
import struct
import subprocess
import sys
import threading
import time
import traceback
from base64 import b64encode
from ctypes import c_int
from datetime import datetime, timezone
from urllib.parse import quote
from urllib.request import Request, urlopen
from urllib.error import URLError, HTTPError

from bcc import BPF, PerfType, PerfSWConfig

from network_trackers import (
    TcpHandshakeTracker,
    TcpLossTracker,
    HostNetHealthTracker,
)


# =============================================================================
# Common helpers
# =============================================================================

BOOT_TO_WALL_OFFSET = time.time() - time.monotonic()


def ktime_to_iso(ktime_ns):
    if not ktime_ns:
        return None
    wall_seconds = (ktime_ns / 1e9) + BOOT_TO_WALL_OFFSET
    return datetime.fromtimestamp(wall_seconds, tz=timezone.utc).strftime(
        "%Y-%m-%d %H:%M:%S.%f")


def now_iso():
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S.%f")


def now_iso_es():
    """ISO-8601 with T separator, accepted by Elasticsearch's default date parser."""
    return datetime.now(timezone.utc).isoformat()


def get_machine_ip():
    try:
        return socket.gethostbyname(socket.gethostname())
    except Exception:
        return "unknown"


TASK_STATE_NAMES = {
    0x0001: "S", 0x0002: "D", 0x0004: "T", 0x0008: "t",
    0x0010: "X", 0x0020: "Z", 0x0040: "P", 0x0080: "I",
    0x0100: "K", 0x0200: "W", 0x0400: "N", 0x0800: "n",
}


def state_to_str(state_val):
    base = state_val & 0xff
    if base == 0:
        return "R"
    parts = [name for bit, name in TASK_STATE_NAMES.items() if bit and (base & bit)]
    return "".join(parts) if parts else "?({})".format(state_val)


def decode_comm(comm_bytes):
    try:
        return bytes(comm_bytes).split(b'\x00', 1)[0].decode('utf-8', errors='replace')
    except Exception:
        return ""


def read_container_pid(host_pid):
    """Read container-view PID for a host PID via /proc/<pid>/status NSpid line.
    Returns host_pid as fallback if not in a PID namespace or read fails."""
    try:
        with open("/proc/{}/status".format(host_pid), "r") as f:
            for line in f:
                if line.startswith("NSpid:"):
                    parts = line.split()
                    # NSpid: <host_pid> <next_ns_pid> ... <innermost_pid>
                    # Last field = innermost (container) PID
                    if len(parts) >= 3:
                        return int(parts[-1])
                    elif len(parts) == 2:
                        return int(parts[1])
                    break
    except (FileNotFoundError, PermissionError, ValueError):
        pass
    return host_pid


# =============================================================================
# Comm cache
# =============================================================================

class CommCache(object):
    def __init__(self, ttl=30, max_size=5000):
        self.ttl = ttl
        self.max_size = max_size
        self._cache = {}
        self._lock = threading.Lock()

    def get(self, pid, tid):
        if pid == 0 or tid == 0:
            return ""
        now = time.time()
        with self._lock:
            cached = self._cache.get((pid, tid))
            if cached and (now - cached[1]) < self.ttl:
                return cached[0]
        try:
            with open("/proc/{}/task/{}/comm".format(pid, tid), "r") as f:
                comm = f.read().strip()
        except Exception:
            comm = ""
        with self._lock:
            self._cache[(pid, tid)] = (comm, now)
            if len(self._cache) > self.max_size:
                self._cache.clear()
        return comm


# =============================================================================
# Thread name resolver  (now also maintains host->container ID map)
# =============================================================================

class ThreadNameResolver(object):
    def __init__(self, pids, interval=30, pyspy_bin="py-spy"):
        self.pids = [int(p) for p in pids]
        self.interval = interval
        self.pyspy_bin = pyspy_bin
        self._names = {}
        # NEW: (host_pid, host_tid) -> (container_pid, container_tid)
        self._host_to_container = {}
        # NEW: host_pid -> container_pid (cached, never changes for a process)
        self._pid_to_container_pid = {}
        self._lock = threading.Lock()
        self._stop = False

    def get(self, pid, tid):
        if pid == 0 or tid == 0:
            return ""
        with self._lock:
            return self._names.get((pid, tid), "")

    def get_container_ids(self, host_pid, host_tid):
        """Returns (container_pid, container_tid) for this host (pid, tid).
        Falls back to host IDs if not in container or not yet mapped."""
        if host_pid == 0 or host_tid == 0:
            return host_pid, host_tid
        with self._lock:
            # Try the full map first (resolved via py-spy refresh)
            ids = self._host_to_container.get((host_pid, host_tid))
            if ids is not None:
                return ids
            # Partial fallback: we know the container PID, but not the TID
            container_pid = self._pid_to_container_pid.get(host_pid, host_pid)
        # Fallback: read the host TID's container TID directly from /proc.
        # Only happens for newly-spawned threads not yet in our refresh map.
        try:
            with open("/proc/{}/task/{}/status".format(host_pid, host_tid), "r") as f:
                for line in f:
                    if line.startswith("NSpid:"):
                        parts = line.split()
                        if len(parts) >= 3:
                            return container_pid, int(parts[-1])
                        elif len(parts) == 2:
                            return container_pid, int(parts[1])
                        break
        except (FileNotFoundError, PermissionError, ValueError):
            pass
        # Last-resort fallback: use host TID as container TID
        return container_pid, host_tid

    def get_host_to_container_tid_map(self):
        """Returns a snapshot of the full {(host_pid, host_tid): (container_pid, container_tid)} map.
        Used by PyStackProfilerTracker to populate its eBPF hash."""
        with self._lock:
            return dict(self._host_to_container)

    def start(self):
        self._refresh_once()
        t = threading.Thread(target=self._refresher_loop, daemon=True)
        t.start()

    def _refresher_loop(self):
        while not self._stop:
            time.sleep(self.interval)
            try:
                self._refresh_once()
            except Exception as ex:
                print("ThreadNameResolver refresh error: {}".format(ex),
                      file=sys.stderr)

    def _refresh_once(self):
        new_names = {}
        new_h2c = {}
        new_pid_map = {}

        for pid in self.pids:
            # Build the container_tid -> host_tid map AND the reverse host->container map
            container_to_host, host_to_container_tid = \
                self._build_container_to_host_tid_map(pid)
            container_pid = read_container_pid(pid)
            new_pid_map[pid] = container_pid

            # Populate host->container TID map for all known TIDs in this PID
            for host_tid, container_tid in host_to_container_tid.items():
                new_h2c[(pid, host_tid)] = (container_pid, container_tid)

            # py-spy thread names
            try:
                proc = subprocess.run(
                    [self.pyspy_bin, "dump", "--pid", str(pid), "--json"],
                    capture_output=True, text=True, timeout=10,
                )
                if proc.returncode != 0:
                    print("py-spy dump pid {} failed: {}".format(
                        pid, proc.stderr.strip()), file=sys.stderr)
                    continue
                names = self._parse_pyspy_json(pid, proc.stdout, container_to_host)
                new_names.update(names)
            except subprocess.TimeoutExpired:
                print("py-spy dump pid {} timed out".format(pid), file=sys.stderr)
            except FileNotFoundError:
                print("py-spy not found at '{}'. Use --pyspy-bin /full/path".format(
                    self.pyspy_bin), file=sys.stderr)
                # Don't return - we still want the host->container map even without py-spy
            except Exception as ex:
                print("py-spy dump pid {} error: {}".format(pid, ex), file=sys.stderr)

        with self._lock:
            self._names.clear()
            self._names.update(new_names)
            self._host_to_container.clear()
            self._host_to_container.update(new_h2c)
            self._pid_to_container_pid.clear()
            self._pid_to_container_pid.update(new_pid_map)
        print("[resolver] refreshed: {} thread names, {} host->container TID mappings".format(
            len(new_names), len(new_h2c)), file=sys.stderr)

    @staticmethod
    def _build_container_to_host_tid_map(host_pid):
        """Returns (container_tid -> host_tid, host_tid -> container_tid)."""
        c_to_h = {}
        h_to_c = {}
        task_dir = "/proc/{}/task".format(host_pid)
        try:
            host_tids = os.listdir(task_dir)
        except (FileNotFoundError, PermissionError):
            return c_to_h, h_to_c

        for host_tid_str in host_tids:
            status_path = "{}/{}/status".format(task_dir, host_tid_str)
            try:
                with open(status_path, "r") as f:
                    for line in f:
                        if line.startswith("NSpid:"):
                            parts = line.split()
                            if len(parts) >= 3:
                                host_tid = int(parts[1])
                                container_tid = int(parts[-1])
                                c_to_h[container_tid] = host_tid
                                h_to_c[host_tid] = container_tid
                            elif len(parts) == 2:
                                host_tid = int(parts[1])
                                c_to_h[host_tid] = host_tid
                                h_to_c[host_tid] = host_tid
                            break
            except (FileNotFoundError, PermissionError):
                continue
        return c_to_h, h_to_c

    @staticmethod
    def _parse_pyspy_json(host_pid, output, container_to_host):
        result = {}
        try:
            data = json.loads(output)
        except json.JSONDecodeError as ex:
            print("py-spy JSON parse error for pid {}: {}".format(host_pid, ex),
                  file=sys.stderr)
            return result
        if not isinstance(data, list):
            return result

        for entry in data:
            container_tid = entry.get("os_thread_id")
            name = entry.get("thread_name")
            if container_tid is None or name is None:
                continue
            host_tid = container_to_host.get(int(container_tid))
            if host_tid is None:
                continue
            result[(host_pid, host_tid)] = name
        return result


# =============================================================================
# Event writer (ClickHouse + Elasticsearch, single thread)
# =============================================================================

# ClickHouse routing
METRIC_TO_CH_TABLE = {
    "gc_pause": "ebpf_gc_pause",
    "gil_wait": "ebpf_gil_wait",
    "off_cpu":  "ebpf_off_cpu",
    "handoff":  "ebpf_handoff",
    # --- network trackers ---
    "tcp_accept":      "ebpf_tcp_accept",
    "tcp_connect":     "ebpf_tcp_connect",
    "tcp_loss":        "ebpf_tcp_loss",
    "host_net_health": "ebpf_host_net_health",
    # --- python stack profiler ---
    "py_stack":        "ebpf_py_stacks",
}
FIELDS_TO_DROP_PER_METRIC = {
    "handoff":  ["queued_time", "pickup_time"],
    "gc_pause": [],
    "gil_wait": [],
    "off_cpu":  [],
    "tcp_accept":      [],
    "tcp_connect":     [],
    "tcp_loss":        [],
    "host_net_health": [],
    "py_stack":        [],
}

# Elasticsearch routing — index name is built from env_name + suffix per metric
METRIC_TO_ES_SUFFIX = {
    "request_queue_size":      "queue-size",
    "request_count":           "request-count",
    "thread_pool_utilisation": "thread-pool-utilisation",
}


class EventWriter(object):
    """
    Single writer thread that handles both ClickHouse and Elasticsearch.

    Routes events by `metric` field:
      - ClickHouse (4 metrics): batched JSONEachRow inserts via HTTP
      - Elasticsearch (3 metrics): per-document POST to /<index>/_doc
        (low volume - 1/sec and 1/15s aggregates - so no batching needed)

    enqueue() is non-blocking. Writer thread polls queue every 0.5s.
    """

    def __init__(self,
                 ch_url=None, ch_user="default", ch_password="", ch_database="default",
                 es_url=None, es_user="elastic", es_password="", es_verify_certs=False,
                 batch_size=1000, flush_interval=5.0, queue_max=100000,
                 env_name=""):
        self.env_name = env_name

        # ClickHouse config
        self.ch_url = ch_url.rstrip("/") if ch_url else None
        self.ch_database = ch_database
        if self.ch_url:
            creds = "{}:{}".format(ch_user, ch_password)
            self._ch_auth_header = "Basic " + b64encode(
                creds.encode("utf-8")).decode("ascii")
        else:
            self._ch_auth_header = None

        # Elasticsearch config
        self.es_url = es_url.rstrip("/") if es_url else None
        if self.es_url:
            creds = "{}:{}".format(es_user, es_password)
            self._es_auth_header = "Basic " + b64encode(
                creds.encode("utf-8")).decode("ascii")
            self._ssl_ctx = ssl.create_default_context()
            if not es_verify_certs:
                self._ssl_ctx.check_hostname = False
                self._ssl_ctx.verify_mode = ssl.CERT_NONE
        else:
            self._es_auth_header = None
            self._ssl_ctx = None

        self.batch_size = batch_size
        self.flush_interval = flush_interval
        self.q = queue.Queue(maxsize=queue_max)

        self._stop = False
        self._thread = None

        self._stats_lock = threading.Lock()
        self.stats = {
            "enqueued": 0,
            "dropped_queue_full": 0,
            "ch_inserted": 0,
            "ch_failed_batches": 0,
            "ch_retries": 0,
            "es_inserted": 0,
            "es_failed": 0,
        }
        self._last_warn_drop = 0

    def enqueue(self, event):
        try:
            self.q.put_nowait(event)
            with self._stats_lock:
                self.stats["enqueued"] += 1
        except queue.Full:
            with self._stats_lock:
                self.stats["dropped_queue_full"] += 1
            now = time.time()
            if now - self._last_warn_drop > 30:
                print("[writer] WARNING: queue full, dropping events. "
                      "Total dropped: {}".format(self.stats["dropped_queue_full"]),
                      file=sys.stderr)
                self._last_warn_drop = now

    def start(self):
        self._thread = threading.Thread(target=self._writer_loop, daemon=True)
        self._thread.start()
        targets = []
        if self.ch_url:
            targets.append("CH={}".format(self.ch_url))
        if self.es_url:
            targets.append("ES={}".format(self.es_url))
        print("[writer] writer thread started, targets: {}".format(
            ", ".join(targets) if targets else "stdout-only"), file=sys.stderr)

    def stop(self, drain_timeout=10.0):
        self._stop = True
        if self._thread:
            self._thread.join(timeout=drain_timeout)

    def _writer_loop(self):
        ch_pending = {m: [] for m in METRIC_TO_CH_TABLE.keys()}
        last_flush = time.time()
        last_stats = time.time()

        while not self._stop:
            try:
                ev = self.q.get(timeout=0.5)
                metric = ev.get("metric")
                if metric in METRIC_TO_CH_TABLE:
                    ch_pending[metric].append(ev)
                elif metric in METRIC_TO_ES_SUFFIX:
                    self._flush_es(metric, ev)
            except queue.Empty:
                pass

            now = time.time()
            # Flush each metric INDEPENDENTLY: on its own size cap, or on the
            # shared age timer. Previously, any single metric hitting batch_size
            # (or the timer firing) flushed ALL tables at once — so the highest-
            # volume metric (off_cpu) dragged every table, including near-idle
            # ones like host_net_health, into emitting a part at its rate. That
            # coupling was the source of the part explosion (87-320 active
            # parts/partition). Now a quiet table only flushes on the age timer.
            time_to_flush = (now - last_flush) >= self.flush_interval
            for metric, batch in ch_pending.items():
                if not batch:
                    continue
                if len(batch) >= self.batch_size or time_to_flush:
                    self._flush_ch_batch(metric, batch)
                    ch_pending[metric] = []
            if time_to_flush:
                last_flush = now

            if now - last_stats > 60:
                self._print_stats()
                last_stats = now

        # Drain on stop
        for metric, batch in ch_pending.items():
            if batch:
                self._flush_ch_batch(metric, batch)
        remaining_ch = []
        while True:
            try:
                ev = self.q.get_nowait()
                m = ev.get("metric")
                if m in METRIC_TO_CH_TABLE:
                    remaining_ch.append(ev)
                elif m in METRIC_TO_ES_SUFFIX:
                    self._flush_es(m, ev)
            except queue.Empty:
                break
        if remaining_ch:
            grouped = {}
            for ev in remaining_ch:
                grouped.setdefault(ev["metric"], []).append(ev)
            for metric, batch in grouped.items():
                self._flush_ch_batch(metric, batch)
        self._print_stats()

    def _flush_ch_batch(self, metric, events):
        if not events or not self.ch_url:
            return
        table = METRIC_TO_CH_TABLE[metric]
        drop_fields = FIELDS_TO_DROP_PER_METRIC.get(metric, [])

        lines = []
        for ev in events:
            row = {k: v for k, v in ev.items() if k != "metric"}
            for f in drop_fields:
                row.pop(f, None)
            if metric == "handoff" and "worker_tid" in row:
                row["tid"] = row["worker_tid"]
            lines.append(json.dumps(row))
        body = "\n".join(lines).encode("utf-8")

        query = "INSERT INTO {}.{} FORMAT JSONEachRow".format(self.ch_database, table)
        url = "{}/?query={}".format(self.ch_url, quote(query))

        last_err = None
        for attempt in range(2):
            try:
                req = Request(url, data=body, method="POST")
                req.add_header("Authorization", self._ch_auth_header)
                req.add_header("Content-Type", "application/x-ndjson")
                with urlopen(req, timeout=10) as resp:
                    resp.read()
                with self._stats_lock:
                    self.stats["ch_inserted"] += len(events)
                return
            except HTTPError as e:
                err_body = ""
                try:
                    err_body = e.read().decode("utf-8", errors="replace")[:500]
                except Exception:
                    pass
                if 400 <= e.code < 500:
                    print("[writer] CH HTTPError {} on {} (no retry): {}".format(
                        e.code, table, err_body), file=sys.stderr)
                    if events:
                        print("[writer]   sample event: {}".format(
                            json.dumps(events[0])[:500]), file=sys.stderr)
                    with self._stats_lock:
                        self.stats["ch_failed_batches"] += 1
                    return
                last_err = e
            except (URLError, socket.timeout, OSError) as e:
                last_err = e
            if attempt == 0:
                with self._stats_lock:
                    self.stats["ch_retries"] += 1
                time.sleep(1.0)

        with self._stats_lock:
            self.stats["ch_failed_batches"] += 1
        print("[writer] CH failed inserting {} events into {} after retry: {}".format(
            len(events), table, last_err), file=sys.stderr)

    def _flush_es(self, metric, event):
        if not self.es_url:
            return
        suffix = METRIC_TO_ES_SUFFIX[metric]
        index = "{}-{}".format(self.env_name, suffix)

        doc = {k: v for k, v in event.items() if k != "metric"}
        body = json.dumps(doc).encode("utf-8")
        url = "{}/{}/_doc".format(self.es_url, index)

        try:
            req = Request(url, data=body, method="POST")
            req.add_header("Authorization", self._es_auth_header)
            req.add_header("Content-Type", "application/json")
            with urlopen(req, timeout=10, context=self._ssl_ctx) as resp:
                resp.read()
            with self._stats_lock:
                self.stats["es_inserted"] += 1
        except HTTPError as e:
            err_body = ""
            try:
                err_body = e.read().decode("utf-8", errors="replace")[:500]
            except Exception:
                pass
            print("[writer] ES HTTPError {} on {}: {}".format(
                e.code, index, err_body), file=sys.stderr)
            with self._stats_lock:
                self.stats["es_failed"] += 1
        except (URLError, socket.timeout, OSError, ssl.SSLError) as e:
            print("[writer] ES error on {}: {}".format(index, e), file=sys.stderr)
            with self._stats_lock:
                self.stats["es_failed"] += 1

    def _print_stats(self):
        with self._stats_lock:
            s = dict(self.stats)
        print("[writer stats] enqueued={} dropped(queue_full)={} "
              "ch_inserted={} ch_failed={} ch_retries={} "
              "es_inserted={} es_failed={} queue_size={}".format(
                  s["enqueued"], s["dropped_queue_full"],
                  s["ch_inserted"], s["ch_failed_batches"], s["ch_retries"],
                  s["es_inserted"], s["es_failed"], self.q.qsize()),
              file=sys.stderr)


# =============================================================================
# Base tracker
# =============================================================================

class BaseTracker(object):
    METRIC_NAME = "base"

    def __init__(self, pids, env_name, machine_ip, resolver, comm_cache,
                 writer=None, also_stdout=False):
        self.pids = [int(p) for p in pids]
        self.env_name = env_name
        self.machine_ip = machine_ip
        self.resolver = resolver
        self.comm_cache = comm_cache
        self.writer = writer
        self.also_stdout = also_stdout
        self.bpf = None

    def pid_filter_clause(self):
        clauses = " && ".join(["pid != %s" % p for p in self.pids])
        return "if (" + clauses + ") { return 0; }"

    def bpf_text(self):
        raise NotImplementedError

    def attach_probes(self, bpf):
        pass

    def perf_buffer_name(self):
        raise NotImplementedError

    def handle_event(self, cpu, data, size):
        raise NotImplementedError

    def base_doc(self, pid, tid, start_ns, end_ns, duration_ms):
        # Enrich with container-view IDs (matches what OTel SpanProcessor sets)
        container_pid, container_tid = self.resolver.get_container_ids(pid, tid)
        return {
            "metric": self.METRIC_NAME,
            "server_name": self.env_name,
            "machine_ip": self.machine_ip,
            "pid": pid,
            "tid": tid,
            "container_pid": container_pid,
            "container_tid": container_tid,
            "start_time": ktime_to_iso(start_ns),
            "end_time": ktime_to_iso(end_ns),
            "duration_ms": duration_ms,
            "published_date": now_iso(),
        }

    def emit(self, doc):
        if self.writer is not None:
            try:
                self.writer.enqueue(doc)
            except Exception as ex:
                print("[{}] enqueue error: {}".format(self.METRIC_NAME, ex),
                      file=sys.stderr)

        if self.also_stdout or self.writer is None:
            try:
                print(json.dumps(doc))
                sys.stdout.flush()
            except Exception as ex:
                print("[{}] stdout error: {}".format(self.METRIC_NAME, ex),
                      file=sys.stderr)

    def safe_handle_event(self, cpu, data, size):
        try:
            self.handle_event(cpu, data, size)
        except Exception as ex:
            print("[{}] handler error: {}".format(self.METRIC_NAME, ex),
                  file=sys.stderr)
            traceback.print_exc(file=sys.stderr)

    def setup(self):
        text = self.bpf_text()
        self.bpf = BPF(text=text)
        self.attach_probes(self.bpf)
        if self.perf_buffer_name():
            self.bpf[self.perf_buffer_name()].open_perf_buffer(
                self.safe_handle_event, page_cnt=128
            )
        print("[{}] tracker initialized".format(self.METRIC_NAME), file=sys.stderr)


# =============================================================================
# GC pause tracker  (unchanged BPF; container_pid/container_tid added via base_doc)
# =============================================================================

class GCPauseTracker(BaseTracker):
    METRIC_NAME = "gc_pause"

    def bpf_text(self):
        text = """
        #include <uapi/linux/ptrace.h>

        struct gc_entry_t {
            u64 ts;
            u64 generation;
        };

        struct gc_event_t {
            u32 pid;
            u32 tid;
            u64 start_ns;
            u64 duration_us;
            u32 generation;
        };

        BPF_HASH(gc_start_ts, u32, struct gc_entry_t);
        BPF_PERF_OUTPUT(gc_events);

        int gc_start(struct pt_regs *ctx)
        {
            u32 pid = bpf_get_current_pid_tgid() >> 32;
            u32 tid = (u32)bpf_get_current_pid_tgid();
            FILTER_PID

            struct gc_entry_t entry = {};
            entry.ts = bpf_ktime_get_ns();
            entry.generation = (u64)PT_REGS_PARM2(ctx);
            gc_start_ts.update(&tid, &entry);
            return 0;
        }

        int gc_end(struct pt_regs *ctx)
        {
            u32 pid = bpf_get_current_pid_tgid() >> 32;
            u32 tid = (u32)bpf_get_current_pid_tgid();
            FILTER_PID

            struct gc_entry_t *entry = gc_start_ts.lookup(&tid);
            if (entry == NULL) return 0;

            u64 now = bpf_ktime_get_ns();
            struct gc_event_t evt = {};
            evt.pid = pid;
            evt.tid = tid;
            evt.start_ns = entry->ts;
            evt.duration_us = (now - entry->ts) / 1000;
            evt.generation = (u32)entry->generation;

            gc_events.perf_submit(ctx, &evt, sizeof(evt));
            gc_start_ts.delete(&tid);
            return 0;
        }
        """
        return text.replace("FILTER_PID", self.pid_filter_clause())

    def perf_buffer_name(self):
        return "gc_events"

    def attach_probes(self, bpf):
        first_pid = self.pids[0]
        python_bin = "/proc/{0}/root/usr/local/bin/python3.11".format(first_pid)
        bpf.attach_uprobe(name=python_bin, sym="gc_collect_main", fn_name="gc_start")
        bpf.attach_uretprobe(name=python_bin, sym="gc_collect_main", fn_name="gc_end")

    def handle_event(self, cpu, data, size):
        e = self.bpf["gc_events"].event(data)
        duration_ms = round(e.duration_us / 1000.0, 3)
        end_ns = e.start_ns + (e.duration_us * 1000)

        doc = self.base_doc(e.pid, e.tid, e.start_ns, end_ns, duration_ms)
        doc["thread_name"] = self.resolver.get(e.pid, e.tid)
        doc["generation"] = e.generation
        self.emit(doc)


# =============================================================================
# GIL wait tracker  (unchanged BPF; container ids added via base_doc;
# holder_container_tid also enriched)
# =============================================================================

class GILWaitTracker(BaseTracker):
    METRIC_NAME = "gil_wait"

    def __init__(self, pids, env_name, machine_ip, resolver, comm_cache,
                 writer=None, also_stdout=False, min_wait_ms=1.0,
                 py_min_ms=0.0, tid_refresh_interval=2.0,
                 py_enable=True):
        super(GILWaitTracker, self).__init__(
            pids, env_name, machine_ip, resolver, comm_cache,
            writer=writer, also_stdout=also_stdout)
        self.min_wait_us = int(min_wait_ms * 1000)
        # Python stack capture. If duration_ms < py_min_ms the py_stack
        # fields are skipped in emitted doc (walk still happens in BPF).
        # py_min_ms=0 => always include (useful for testing).
        self.py_min_ms = py_min_ms
        # Safety flag: when False, don't populate the runtime map -> BPF's
        # null-check on off_cpu_target_pid_to_runtime skips walk entirely.
        # Use to disable py_stack in production without redeploy.
        self.py_enable = py_enable
        # (pid, code_addr) -> (func, file, lineno) cache
        self._code_cache = {}
        self.tid_refresh_interval = tid_refresh_interval
        self._refresher_stop = False
        self._refresher_thread = None

    def bpf_text(self):
        text = """
        #include <uapi/linux/ptrace.h>

        #define PY_MAX_STACK_DEPTH 20

        #define RUNTIME_INTERPRETERS_OFFSET     OFFSET_RUNTIME_INTERPRETERS
        #define INTERPRETERS_HEAD_OFFSET        OFFSET_INTERPRETERS_HEAD
        #define ISTATE_THREADS_OFFSET           OFFSET_ISTATE_THREADS
        #define THREADS_HEAD_OFFSET             OFFSET_THREADS_HEAD
        #define TSTATE_NEXT_OFFSET              OFFSET_TSTATE_NEXT
        #define TSTATE_CFRAME_OFFSET            OFFSET_TSTATE_CFRAME
        #define TSTATE_NATIVE_TID_OFFSET        OFFSET_TSTATE_NATIVE_TID
        #define CFRAME_CURRENT_FRAME_OFFSET     OFFSET_CFRAME_CURRENT_FRAME
        #define IFRAME_F_CODE_OFFSET            OFFSET_IFRAME_F_CODE
        #define IFRAME_PREVIOUS_OFFSET          OFFSET_IFRAME_PREVIOUS

        struct py_stack_t {
            u32 depth;
            u64 code_addrs[PY_MAX_STACK_DEPTH];
        };

        struct wait_info_t {
            u64 ts;
            u32 holder_tid;
            // Waiter's Python stack captured at gil_wait_enter (retrieved
            // at gil_wait_exit and copied into the emitted event).
            struct py_stack_t waiter_stack;
        };

        BPF_HASH(gil_wait_start, u32, struct wait_info_t);
        BPF_HASH(gil_holder, u32, u32);

        // Populated by userspace: target Python pids -> _PyRuntime address
        BPF_HASH(gil_target_pid_to_runtime, u32, u64, 64);
        // Populated by userspace from /proc/<pid>/task/<tid>/status NSpid
        BPF_HASH(gil_host_to_container_tid, u32, u32, 8192);
        // Holder's Python stack captured at drop_gil_enter, keyed by holder tid.
        // Consumed at gil_wait_exit (lookup by wait->holder_tid).
        BPF_HASH(gil_holder_py_stack, u32, struct py_stack_t, 10240);
        // Per-CPU scratch to build a py_stack_t without blowing the BPF stack
        BPF_PERCPU_ARRAY(gil_py_scratch, struct py_stack_t, 1);

        struct gil_event_t {
            u32 pid;
            u32 tid;
            u32 holder_tid;
            u64 start_ns;
            u64 duration_us;
            char comm[16];
            u32 waiter_py_stack_depth;
            u64 waiter_py_code_addrs[PY_MAX_STACK_DEPTH];
            u32 holder_py_stack_depth;
            u64 holder_py_code_addrs[PY_MAX_STACK_DEPTH];
        };

        BPF_PERF_OUTPUT(gil_events);

        int gil_wait_enter(struct pt_regs *ctx)
        {
            u32 pid = bpf_get_current_pid_tgid() >> 32;
            u32 tid = (u32)bpf_get_current_pid_tgid();
            FILTER_PID

            struct wait_info_t wait = {};
            wait.ts = bpf_ktime_get_ns();

            u32 *holder = gil_holder.lookup(&pid);
            wait.holder_tid = (holder != NULL) ? *holder : 0;

            // ---- Walk WAITER's Python stack (current context = waiter) ----
            u64 *py_runtime_p = gil_target_pid_to_runtime.lookup(&pid);
            if (py_runtime_p) {
                u32 *container_tid_p = gil_host_to_container_tid.lookup(&tid);
                if (container_tid_p) {
                    u64 py_runtime_addr = *py_runtime_p;
                    u32 target_container_tid = *container_tid_p;

                    u64 interp_addr = 0;
                    u64 interp_ptr_addr = py_runtime_addr +
                        RUNTIME_INTERPRETERS_OFFSET + INTERPRETERS_HEAD_OFFSET;
                    if (bpf_probe_read(&interp_addr, sizeof(interp_addr),
                            (void *)interp_ptr_addr) == 0 && interp_addr) {

                        u64 tstate_addr = 0;
                        u64 tstate_ptr_addr = interp_addr +
                            ISTATE_THREADS_OFFSET + THREADS_HEAD_OFFSET;
                        if (bpf_probe_read(&tstate_addr, sizeof(tstate_addr),
                                (void *)tstate_ptr_addr) == 0) {

                            u64 native_tid = 0;
                            u64 matched_tstate = 0;

                            #define GILW_CHECK_ONE_THREAD(idx) \
                                if (!tstate_addr) goto gilw_thread_done; \
                                if (bpf_probe_read(&native_tid, sizeof(native_tid), \
                                        (void *)(tstate_addr + TSTATE_NATIVE_TID_OFFSET)) != 0) \
                                    goto gilw_thread_done; \
                                if ((u32)native_tid == target_container_tid) { \
                                    matched_tstate = tstate_addr; \
                                    goto gilw_thread_done; \
                                } \
                                { u64 next_t = 0; \
                                  if (bpf_probe_read(&next_t, sizeof(next_t), \
                                          (void *)(tstate_addr + TSTATE_NEXT_OFFSET)) != 0) \
                                      goto gilw_thread_done; \
                                  tstate_addr = next_t; }

                            GILW_CHECK_ONE_THREAD(0)  GILW_CHECK_ONE_THREAD(1)
                            GILW_CHECK_ONE_THREAD(2)  GILW_CHECK_ONE_THREAD(3)
                            GILW_CHECK_ONE_THREAD(4)  GILW_CHECK_ONE_THREAD(5)
                            GILW_CHECK_ONE_THREAD(6)  GILW_CHECK_ONE_THREAD(7)
                            GILW_CHECK_ONE_THREAD(8)  GILW_CHECK_ONE_THREAD(9)
                            GILW_CHECK_ONE_THREAD(10) GILW_CHECK_ONE_THREAD(11)
                            GILW_CHECK_ONE_THREAD(12) GILW_CHECK_ONE_THREAD(13)
                            GILW_CHECK_ONE_THREAD(14) GILW_CHECK_ONE_THREAD(15)
                            GILW_CHECK_ONE_THREAD(16) GILW_CHECK_ONE_THREAD(17)
                            GILW_CHECK_ONE_THREAD(18) GILW_CHECK_ONE_THREAD(19)
                            GILW_CHECK_ONE_THREAD(20) GILW_CHECK_ONE_THREAD(21)
                            GILW_CHECK_ONE_THREAD(22) GILW_CHECK_ONE_THREAD(23)
                            GILW_CHECK_ONE_THREAD(24) GILW_CHECK_ONE_THREAD(25)
                            GILW_CHECK_ONE_THREAD(26) GILW_CHECK_ONE_THREAD(27)
                            GILW_CHECK_ONE_THREAD(28) GILW_CHECK_ONE_THREAD(29)
                            GILW_CHECK_ONE_THREAD(30) GILW_CHECK_ONE_THREAD(31)

                        gilw_thread_done:
                            if (matched_tstate) {
                                u64 cframe_addr = 0;
                                if (bpf_probe_read(&cframe_addr, sizeof(cframe_addr),
                                        (void *)(matched_tstate +
                                            TSTATE_CFRAME_OFFSET)) == 0
                                    && cframe_addr) {
                                    u64 frame_addr = 0;
                                    bpf_probe_read(&frame_addr, sizeof(frame_addr),
                                        (void *)(cframe_addr +
                                            CFRAME_CURRENT_FRAME_OFFSET));
                                    u64 code_addr;
                                    u64 prev;

                                    #define GILW_WALK_ONE_FRAME(idx) \
                                        if (!frame_addr) goto gilw_frame_done; \
                                        code_addr = 0; \
                                        if (bpf_probe_read(&code_addr, sizeof(code_addr), \
                                                (void *)(frame_addr + IFRAME_F_CODE_OFFSET)) != 0) \
                                            goto gilw_frame_done; \
                                        if (code_addr) { \
                                            wait.waiter_stack.code_addrs[idx] = code_addr; \
                                            wait.waiter_stack.depth = idx + 1; \
                                        } \
                                        prev = 0; \
                                        if (bpf_probe_read(&prev, sizeof(prev), \
                                                (void *)(frame_addr + IFRAME_PREVIOUS_OFFSET)) != 0) \
                                            goto gilw_frame_done; \
                                        frame_addr = prev;

                                    GILW_WALK_ONE_FRAME(0)  GILW_WALK_ONE_FRAME(1)
                                    GILW_WALK_ONE_FRAME(2)  GILW_WALK_ONE_FRAME(3)
                                    GILW_WALK_ONE_FRAME(4)  GILW_WALK_ONE_FRAME(5)
                                    GILW_WALK_ONE_FRAME(6)  GILW_WALK_ONE_FRAME(7)
                                    GILW_WALK_ONE_FRAME(8)  GILW_WALK_ONE_FRAME(9)
                                    GILW_WALK_ONE_FRAME(10) GILW_WALK_ONE_FRAME(11)
                                    GILW_WALK_ONE_FRAME(12) GILW_WALK_ONE_FRAME(13)
                                    GILW_WALK_ONE_FRAME(14) GILW_WALK_ONE_FRAME(15)
                                    GILW_WALK_ONE_FRAME(16) GILW_WALK_ONE_FRAME(17)
                                    GILW_WALK_ONE_FRAME(18) GILW_WALK_ONE_FRAME(19)
                                gilw_frame_done:
                                    ;
                                }
                            }
                        }
                    }
                }
            }
            // ---- end waiter walk ----

            gil_wait_start.update(&tid, &wait);
            return 0;
        }

        int gil_wait_exit(struct pt_regs *ctx)
        {
            u32 pid = bpf_get_current_pid_tgid() >> 32;
            u32 tid = (u32)bpf_get_current_pid_tgid();
            FILTER_PID

            struct wait_info_t *wait = gil_wait_start.lookup(&tid);
            if (wait == NULL) return 0;

            u64 now = bpf_ktime_get_ns();
            u64 delta_us = (now - wait->ts) / 1000;

            if (delta_us >= MIN_WAIT_US) {
                struct gil_event_t evt = {};
                evt.pid = pid;
                evt.tid = tid;
                evt.holder_tid = wait->holder_tid;
                evt.start_ns = wait->ts;
                evt.duration_us = delta_us;
                bpf_get_current_comm(&evt.comm, sizeof(evt.comm));

                // Copy waiter's Python stack from wait_info into event
                evt.waiter_py_stack_depth = wait->waiter_stack.depth;
                __builtin_memcpy(&evt.waiter_py_code_addrs,
                                 wait->waiter_stack.code_addrs,
                                 sizeof(evt.waiter_py_code_addrs));

                // Look up holder's Python stack captured at drop_gil_enter
                if (wait->holder_tid != 0) {
                    struct py_stack_t *holder_stk =
                        gil_holder_py_stack.lookup(&wait->holder_tid);
                    if (holder_stk) {
                        evt.holder_py_stack_depth = holder_stk->depth;
                        __builtin_memcpy(&evt.holder_py_code_addrs,
                                         holder_stk->code_addrs,
                                         sizeof(evt.holder_py_code_addrs));
                    }
                }

                gil_events.perf_submit(ctx, &evt, sizeof(evt));
            }

            gil_wait_start.delete(&tid);
            gil_holder.update(&pid, &tid);
            return 0;
        }

        int gil_drop_enter(struct pt_regs *ctx)
        {
            u32 pid = bpf_get_current_pid_tgid() >> 32;
            u32 tid = (u32)bpf_get_current_pid_tgid();
            FILTER_PID

            // ---- Walk HOLDER's Python stack (current context = holder about
            //      to drop the GIL). Store keyed by tid so that whoever
            //      picks it up next can look it up in gil_wait_exit.
            u64 *py_runtime_p = gil_target_pid_to_runtime.lookup(&pid);
            if (py_runtime_p) {
                u32 *container_tid_p = gil_host_to_container_tid.lookup(&tid);
                if (container_tid_p) {
                    int zero = 0;
                    struct py_stack_t *pystk =
                        gil_py_scratch.lookup(&zero);
                    if (pystk) {
                        __builtin_memset(pystk, 0, sizeof(*pystk));

                        u64 py_runtime_addr = *py_runtime_p;
                        u32 target_container_tid = *container_tid_p;

                        u64 interp_addr = 0;
                        u64 interp_ptr_addr = py_runtime_addr +
                            RUNTIME_INTERPRETERS_OFFSET + INTERPRETERS_HEAD_OFFSET;
                        if (bpf_probe_read(&interp_addr, sizeof(interp_addr),
                                (void *)interp_ptr_addr) == 0 && interp_addr) {

                            u64 tstate_addr = 0;
                            u64 tstate_ptr_addr = interp_addr +
                                ISTATE_THREADS_OFFSET + THREADS_HEAD_OFFSET;
                            if (bpf_probe_read(&tstate_addr, sizeof(tstate_addr),
                                    (void *)tstate_ptr_addr) == 0) {

                                u64 native_tid = 0;
                                u64 matched_tstate = 0;

                                #define GILD_CHECK_ONE_THREAD(idx) \
                                    if (!tstate_addr) goto gild_thread_done; \
                                    if (bpf_probe_read(&native_tid, sizeof(native_tid), \
                                            (void *)(tstate_addr + TSTATE_NATIVE_TID_OFFSET)) != 0) \
                                        goto gild_thread_done; \
                                    if ((u32)native_tid == target_container_tid) { \
                                        matched_tstate = tstate_addr; \
                                        goto gild_thread_done; \
                                    } \
                                    { u64 next_t = 0; \
                                      if (bpf_probe_read(&next_t, sizeof(next_t), \
                                              (void *)(tstate_addr + TSTATE_NEXT_OFFSET)) != 0) \
                                          goto gild_thread_done; \
                                      tstate_addr = next_t; }

                                GILD_CHECK_ONE_THREAD(0)  GILD_CHECK_ONE_THREAD(1)
                                GILD_CHECK_ONE_THREAD(2)  GILD_CHECK_ONE_THREAD(3)
                                GILD_CHECK_ONE_THREAD(4)  GILD_CHECK_ONE_THREAD(5)
                                GILD_CHECK_ONE_THREAD(6)  GILD_CHECK_ONE_THREAD(7)
                                GILD_CHECK_ONE_THREAD(8)  GILD_CHECK_ONE_THREAD(9)
                                GILD_CHECK_ONE_THREAD(10) GILD_CHECK_ONE_THREAD(11)
                                GILD_CHECK_ONE_THREAD(12) GILD_CHECK_ONE_THREAD(13)
                                GILD_CHECK_ONE_THREAD(14) GILD_CHECK_ONE_THREAD(15)
                                GILD_CHECK_ONE_THREAD(16) GILD_CHECK_ONE_THREAD(17)
                                GILD_CHECK_ONE_THREAD(18) GILD_CHECK_ONE_THREAD(19)
                                GILD_CHECK_ONE_THREAD(20) GILD_CHECK_ONE_THREAD(21)
                                GILD_CHECK_ONE_THREAD(22) GILD_CHECK_ONE_THREAD(23)
                                GILD_CHECK_ONE_THREAD(24) GILD_CHECK_ONE_THREAD(25)
                                GILD_CHECK_ONE_THREAD(26) GILD_CHECK_ONE_THREAD(27)
                                GILD_CHECK_ONE_THREAD(28) GILD_CHECK_ONE_THREAD(29)
                                GILD_CHECK_ONE_THREAD(30) GILD_CHECK_ONE_THREAD(31)

                            gild_thread_done:
                                if (matched_tstate) {
                                    u64 cframe_addr = 0;
                                    if (bpf_probe_read(&cframe_addr, sizeof(cframe_addr),
                                            (void *)(matched_tstate +
                                                TSTATE_CFRAME_OFFSET)) == 0
                                        && cframe_addr) {
                                        u64 frame_addr = 0;
                                        bpf_probe_read(&frame_addr, sizeof(frame_addr),
                                            (void *)(cframe_addr +
                                                CFRAME_CURRENT_FRAME_OFFSET));
                                        u64 code_addr;
                                        u64 prev;

                                        #define GILD_WALK_ONE_FRAME(idx) \
                                            if (!frame_addr) goto gild_frame_done; \
                                            code_addr = 0; \
                                            if (bpf_probe_read(&code_addr, sizeof(code_addr), \
                                                    (void *)(frame_addr + IFRAME_F_CODE_OFFSET)) != 0) \
                                                goto gild_frame_done; \
                                            if (code_addr) { \
                                                pystk->code_addrs[idx] = code_addr; \
                                                pystk->depth = idx + 1; \
                                            } \
                                            prev = 0; \
                                            if (bpf_probe_read(&prev, sizeof(prev), \
                                                    (void *)(frame_addr + IFRAME_PREVIOUS_OFFSET)) != 0) \
                                                goto gild_frame_done; \
                                            frame_addr = prev;

                                        GILD_WALK_ONE_FRAME(0)  GILD_WALK_ONE_FRAME(1)
                                        GILD_WALK_ONE_FRAME(2)  GILD_WALK_ONE_FRAME(3)
                                        GILD_WALK_ONE_FRAME(4)  GILD_WALK_ONE_FRAME(5)
                                        GILD_WALK_ONE_FRAME(6)  GILD_WALK_ONE_FRAME(7)
                                        GILD_WALK_ONE_FRAME(8)  GILD_WALK_ONE_FRAME(9)
                                        GILD_WALK_ONE_FRAME(10) GILD_WALK_ONE_FRAME(11)
                                        GILD_WALK_ONE_FRAME(12) GILD_WALK_ONE_FRAME(13)
                                        GILD_WALK_ONE_FRAME(14) GILD_WALK_ONE_FRAME(15)
                                        GILD_WALK_ONE_FRAME(16) GILD_WALK_ONE_FRAME(17)
                                        GILD_WALK_ONE_FRAME(18) GILD_WALK_ONE_FRAME(19)
                                    gild_frame_done:
                                        ;
                                    }
                                }
                            }
                        }

                        if (pystk->depth > 0) {
                            gil_holder_py_stack.update(&tid, pystk);
                        }
                    }
                }
            }
            // ---- end holder walk ----

            u32 zero = 0;
            gil_holder.update(&pid, &zero);
            return 0;
        }
        """
        text = text.replace("FILTER_PID", self.pid_filter_clause())
        text = text.replace("MIN_WAIT_US", str(self.min_wait_us))
        # Substitute PY311 struct offsets
        text = (text
            .replace("OFFSET_RUNTIME_INTERPRETERS", str(PY311_OFFSETS["runtime_interpreters"]))
            .replace("OFFSET_INTERPRETERS_HEAD", str(PY311_OFFSETS["interpreters_head"]))
            .replace("OFFSET_ISTATE_THREADS", str(PY311_OFFSETS["istate_threads"]))
            .replace("OFFSET_THREADS_HEAD", str(PY311_OFFSETS["threads_head"]))
            .replace("OFFSET_TSTATE_NEXT", str(PY311_OFFSETS["tstate_next"]))
            .replace("OFFSET_TSTATE_CFRAME", str(PY311_OFFSETS["tstate_cframe"]))
            .replace("OFFSET_TSTATE_NATIVE_TID", str(PY311_OFFSETS["tstate_native_thread_id"]))
            .replace("OFFSET_CFRAME_CURRENT_FRAME", str(PY311_OFFSETS["cframe_current_frame"]))
            .replace("OFFSET_IFRAME_F_CODE", str(PY311_OFFSETS["iframe_f_code"]))
            .replace("OFFSET_IFRAME_PREVIOUS", str(PY311_OFFSETS["iframe_previous"]))
        )
        return text

    def perf_buffer_name(self):
        return "gil_events"

    def attach_probes(self, bpf):
        first_pid = self.pids[0]
        python_bin = "/proc/{0}/root/usr/local/bin/python3.11".format(first_pid)
        bpf.attach_uprobe(name=python_bin, sym="take_gil", fn_name="gil_wait_enter")
        bpf.attach_uretprobe(name=python_bin, sym="take_gil", fn_name="gil_wait_exit")
        bpf.attach_uprobe(name=python_bin, sym="drop_gil", fn_name="gil_drop_enter")

    # -------- Python stack helpers (mirror OffCPUStackTracker) --------
    # Duplicated intentionally so this tracker stays self-contained.

    _MAX_USER_ADDR = 0x0000ffffffffffff

    @classmethod
    def _is_valid_user_addr(cls, addr):
        return 0 < addr <= cls._MAX_USER_ADDR

    def _find_py_runtime_addr(self, pid):
        """Locate _PyRuntime in the target process's libpython."""
        libpython_base = None
        libpython_container_path = None
        try:
            with open("/proc/{}/maps".format(pid)) as f:
                for line in f:
                    if "libpython3.11" in line or "/python3.11" in line:
                        parts = line.split()
                        if "r-xp" in parts[1] or "r--p" in parts[1]:
                            libpython_base = int(parts[0].split("-")[0], 16)
                            libpython_container_path = parts[-1]
                            break
            if not libpython_base:
                with open("/proc/{}/maps".format(pid)) as f:
                    parts = f.readline().split()
                    libpython_base = int(parts[0].split("-")[0], 16)
                    libpython_container_path = parts[-1]
        except (FileNotFoundError, PermissionError) as ex:
            print("[gil_wait] cannot read /proc/{}/maps: {}".format(pid, ex),
                  file=sys.stderr)
            return None

        libpython_host_path = "/proc/{}/root{}".format(
            pid, libpython_container_path)
        if not os.path.exists(libpython_host_path):
            libpython_host_path = libpython_container_path

        py_runtime_offset = None
        for nm_args in (["nm", "-D", libpython_host_path],
                        ["nm", libpython_host_path]):
            try:
                result = subprocess.run(nm_args, capture_output=True,
                                        text=True, check=False)
            except FileNotFoundError:
                print("[gil_wait] nm not found", file=sys.stderr)
                return None
            for line in result.stdout.splitlines():
                parts = line.split()
                if len(parts) >= 3 and parts[-1] == "_PyRuntime":
                    try:
                        py_runtime_offset = int(parts[0], 16)
                        break
                    except ValueError:
                        continue
            if py_runtime_offset is not None:
                break

        if py_runtime_offset is None:
            return None

        addr = libpython_base + py_runtime_offset
        print("[gil_wait] pid {} _PyRuntime address: 0x{:x}".format(pid, addr),
              file=sys.stderr)
        return addr

    def _refresh_container_tid_map(self):
        """Populate gil_host_to_container_tid via /proc NSpid lines."""
        if self.bpf is None:
            return
        try:
            bpf_map = self.bpf["gil_host_to_container_tid"]
        except KeyError:
            return
        for pid in self.pids:
            task_dir = "/proc/{}/task".format(pid)
            try:
                host_tids = os.listdir(task_dir)
            except (FileNotFoundError, PermissionError):
                continue
            for host_tid_str in host_tids:
                status_path = "{}/{}/status".format(task_dir, host_tid_str)
                try:
                    with open(status_path, "r") as f:
                        for line in f:
                            if line.startswith("NSpid:"):
                                parts = line.split()
                                if len(parts) >= 3:
                                    host_tid = int(parts[1])
                                    container_tid = int(parts[-1])
                                elif len(parts) == 2:
                                    host_tid = int(parts[1])
                                    container_tid = host_tid
                                else:
                                    break
                                try:
                                    bpf_map[ctypes.c_uint32(host_tid)] = \
                                        ctypes.c_uint32(container_tid)
                                except Exception:
                                    pass
                                break
                except (FileNotFoundError, PermissionError):
                    continue

    def _read_python_string(self, pid, addr):
        if not self._is_valid_user_addr(addr):
            return ""
        try:
            with open("/proc/{}/mem".format(pid), "rb") as mem:
                mem.seek(addr + PY311_OFFSETS["unicode_length"])
                length = struct.unpack("<Q", mem.read(8))[0]
                if length == 0 or length > 1024:
                    return ""
                mem.seek(addr + PY311_OFFSETS["unicode_data"])
                data = mem.read(min(length, 256))
                return data.decode("utf-8", errors="replace")
        except (OSError, struct.error, ValueError, OverflowError):
            return ""

    def _resolve_code(self, pid, code_addr):
        key = (pid, code_addr)
        cached = self._code_cache.get(key)
        if cached is not None:
            return cached
        if not self._is_valid_user_addr(code_addr):
            result = ("<unknown>", "<unknown>", 0)
            self._code_cache[key] = result
            return result
        try:
            with open("/proc/{}/mem".format(pid), "rb") as mem:
                mem.seek(code_addr + PY311_OFFSETS["code_co_name"])
                name_addr = struct.unpack("<Q", mem.read(8))[0]
                mem.seek(code_addr + PY311_OFFSETS["code_co_filename"])
                file_addr = struct.unpack("<Q", mem.read(8))[0]
                mem.seek(code_addr + PY311_OFFSETS["code_co_firstlineno"])
                lineno = struct.unpack("<i", mem.read(4))[0]
            func_name = self._read_python_string(pid, name_addr)
            filename = self._read_python_string(pid, file_addr)
            result = (func_name, filename, lineno)
        except (OSError, struct.error, ValueError, OverflowError):
            result = ("<unknown>", "<unknown>", 0)
        self._code_cache[key] = result
        return result

    def _refresher_loop(self):
        while not self._refresher_stop:
            time.sleep(self.tid_refresh_interval)
            try:
                self._refresh_container_tid_map()
            except Exception as ex:
                print("[gil_wait] tid refresh error: {}".format(ex),
                      file=sys.stderr)

    def stop(self):
        self._refresher_stop = True

    def setup(self):
        # BaseTracker.setup does BPF(text=...), attach_probes, open_perf_buffer
        super(GILWaitTracker, self).setup()

        if not self.py_enable:
            # Safety flag: py_stack disabled. BPF walk still compiled but
            # gil_target_pid_to_runtime map stays empty -> BPF's null check
            # (`if (py_runtime_p)`) short-circuits the walk on every event.
            # Zero py stacks emitted. Cost: one hash lookup per take_gil.
            print("[gil_wait] python stack capture DISABLED "
                  "(--no-gil-py-enable)", file=sys.stderr)
            return

        # Populate the pid -> _PyRuntime address map so BPF can walk the
        # Python thread state chain for target processes taking/dropping GIL.
        # Non-Python pids or pids where _PyRuntime can't be found are simply
        # skipped (gil_wait still works, just without Python stacks).
        runtime_map = self.bpf["gil_target_pid_to_runtime"]
        any_py_loaded = False
        for pid in self.pids:
            addr = self._find_py_runtime_addr(pid)
            if addr is None:
                continue
            try:
                runtime_map[ctypes.c_uint32(pid)] = ctypes.c_uint64(addr)
                any_py_loaded = True
            except Exception as ex:
                print("[gil_wait] failed to add pid {} to runtime map: {}".format(
                    pid, ex), file=sys.stderr)
        if any_py_loaded:
            self._refresh_container_tid_map()
            print("[gil_wait] python stack capture enabled", file=sys.stderr)
        else:
            print("[gil_wait] no python pids resolvable; py_stack will be empty",
                  file=sys.stderr)

        # Start periodic tid refresher for newly-spawned worker threads
        self._refresher_thread = threading.Thread(
            target=self._refresher_loop, daemon=True)
        self._refresher_thread.start()

    def _resolve_py_stack(self, pid, depth, code_addrs):
        """Resolve code_addrs into a semicolon-joined 'func (file:line)' string,
        root-first (flamegraph convention)."""
        if depth <= 0:
            return ""
        frames = []
        for i in range(depth):
            addr = code_addrs[i]
            if addr == 0:
                continue
            func_name, filename, lineno = self._resolve_code(pid, addr)
            frames.append("{} ({}:{})".format(
                func_name, filename or "?", lineno))
        return ";".join(reversed(frames))

    def handle_event(self, cpu, data, size):
        e = self.bpf["gil_events"].event(data)
        duration_ms = round(e.duration_us / 1000.0, 3)
        end_ns = e.start_ns + (e.duration_us * 1000)

        doc = self.base_doc(e.pid, e.tid, e.start_ns, end_ns, duration_ms)
        doc["comm"] = decode_comm(e.comm)
        doc["thread_name"] = self.resolver.get(e.pid, e.tid)
        doc["holder_tid"] = e.holder_tid
        doc["holder_thread_name"] = (
            self.resolver.get(e.pid, e.holder_tid) if e.holder_tid else ""
        )
        # Container-view holder_tid (matches OTel span thread.id when GIL holder
        # is a request handler thread)
        if e.holder_tid:
            _, holder_container_tid = self.resolver.get_container_ids(
                e.pid, e.holder_tid)
            doc["holder_container_tid"] = holder_container_tid
        else:
            doc["holder_container_tid"] = 0

        # Resolve Python stacks. Skip resolution if event is small enough per
        # py_min_ms threshold, but still emit the depths so downstream can tell
        # walking succeeded vs failed.
        waiter_depth = int(e.waiter_py_stack_depth) if hasattr(
            e, "waiter_py_stack_depth") else 0
        holder_depth = int(e.holder_py_stack_depth) if hasattr(
            e, "holder_py_stack_depth") else 0

        waiter_stack_str = ""
        holder_stack_str = ""
        if duration_ms >= self.py_min_ms:
            if waiter_depth > 0:
                waiter_stack_str = self._resolve_py_stack(
                    e.pid, waiter_depth, e.waiter_py_code_addrs)
            if holder_depth > 0 and e.holder_tid != 0:
                holder_stack_str = self._resolve_py_stack(
                    e.pid, holder_depth, e.holder_py_code_addrs)

        doc["waiter_py_stack"] = waiter_stack_str
        doc["waiter_py_stack_depth"] = waiter_depth
        doc["holder_py_stack"] = holder_stack_str
        doc["holder_py_stack_depth"] = holder_depth
        self.emit(doc)


# =============================================================================
# Off-CPU + run-queue + stack tracker  (unchanged BPF; container ids via base_doc)
# =============================================================================

class OffCPUStackTracker(BaseTracker):
    METRIC_NAME = "off_cpu"

    def __init__(self, pids, env_name, machine_ip, resolver, comm_cache,
                 writer=None, also_stdout=False,
                 min_total_ms=20.0, max_stack_depth=20,
                 tid_refresh_interval=2.0, tid_miss_refresh_cooldown_s=0.5,
                 py_min_ms=0.0, py_enable=True):
        super(OffCPUStackTracker, self).__init__(
            pids, env_name, machine_ip, resolver, comm_cache,
            writer=writer, also_stdout=also_stdout)
        self.min_total_us = int(min_total_ms * 1000)
        self.max_stack_depth = max_stack_depth
        self._target_pids = set(self.pids)
        self._tid_to_pid = {}
        self._last_refresh = 0
        # Periodic refresh interval, and cooldown so consecutive misses don't
        # hammer /proc. Old code used a 10s gate on miss which dropped ~46%
        # of events on gthread workers because new tids spawn faster than 10s.
        self._tid_refresh_interval = tid_refresh_interval
        self._tid_miss_refresh_cooldown_s = tid_miss_refresh_cooldown_s
        self._refresher_stop = False
        self._refresher_thread = None
        # Python stack capture at off-CPU time. If total_ms < py_min_ms the
        # py_stack field is skipped in the emitted doc (walk still happens
        # in BPF). py_min_ms=0 => always include (useful for testing).
        self.py_min_ms = py_min_ms
        # Safety flag: when False, don't populate the runtime map -> BPF's
        # null-check on off_cpu_target_pid_to_runtime skips walk entirely.
        # Use to disable py_stack in production without redeploy.
        self.py_enable = py_enable
        # code_addr -> (func, file, lineno). Keyed per-pid to avoid collisions
        # across processes with different libpython address spaces.
        self._code_cache = {}
        self._refresh_tid_map()

    def _refresh_tid_map(self):
        new_map = {}
        for pid in self._target_pids:
            task_dir = "/proc/{}/task".format(pid)
            try:
                for tid_str in os.listdir(task_dir):
                    new_map[int(tid_str)] = pid
            except (FileNotFoundError, PermissionError):
                continue
        self._tid_to_pid = new_map
        self._last_refresh = time.time()

    def _resolve_pid_for_tid(self, tid):
        pid = self._tid_to_pid.get(tid)
        # On miss, refresh if last refresh was more than cooldown ago.
        # (Was 10s gate before, which dropped ~46% of events for gthread workers.)
        if pid is None and (time.time() - self._last_refresh) > self._tid_miss_refresh_cooldown_s:
            self._refresh_tid_map()
            pid = self._tid_to_pid.get(tid)
        return pid

    def _refresher_loop(self):
        while not self._refresher_stop:
            time.sleep(self._tid_refresh_interval)
            try:
                self._refresh_tid_map()
            except Exception as ex:
                print("[off_cpu] tid refresh error: {}".format(ex),
                      file=sys.stderr)
            # Also keep the BPF host->container_tid map fresh so newly
            # spawned Python threads get resolved during the walk.
            try:
                self._refresh_container_tid_map()
            except Exception as ex:
                print("[off_cpu] container tid refresh error: {}".format(ex),
                      file=sys.stderr)

    def stop(self):
        self._refresher_stop = True

    # -------- Python stack helpers (mirror PyStackProfilerTracker) --------
    # Duplicated intentionally so this tracker stays self-contained.

    # 48-bit userspace canonical addresses (see PyStackProfilerTracker for
    # rationale). Anything higher = kernel/garbage/race.
    _MAX_USER_ADDR = 0x0000ffffffffffff

    @classmethod
    def _is_valid_user_addr(cls, addr):
        return 0 < addr <= cls._MAX_USER_ADDR

    def _find_py_runtime_addr(self, pid):
        """Locate _PyRuntime in the target process's libpython."""
        libpython_base = None
        libpython_container_path = None
        try:
            with open("/proc/{}/maps".format(pid)) as f:
                for line in f:
                    if "libpython3.11" in line or "/python3.11" in line:
                        parts = line.split()
                        if "r-xp" in parts[1] or "r--p" in parts[1]:
                            libpython_base = int(parts[0].split("-")[0], 16)
                            libpython_container_path = parts[-1]
                            break
            if not libpython_base:
                with open("/proc/{}/maps".format(pid)) as f:
                    parts = f.readline().split()
                    libpython_base = int(parts[0].split("-")[0], 16)
                    libpython_container_path = parts[-1]
        except (FileNotFoundError, PermissionError) as ex:
            print("[off_cpu] cannot read /proc/{}/maps: {}".format(pid, ex),
                  file=sys.stderr)
            return None

        libpython_host_path = "/proc/{}/root{}".format(
            pid, libpython_container_path)
        if not os.path.exists(libpython_host_path):
            libpython_host_path = libpython_container_path

        py_runtime_offset = None
        for nm_args in (["nm", "-D", libpython_host_path],
                        ["nm", libpython_host_path]):
            try:
                result = subprocess.run(nm_args, capture_output=True,
                                        text=True, check=False)
            except FileNotFoundError:
                print("[off_cpu] nm not found", file=sys.stderr)
                return None
            for line in result.stdout.splitlines():
                parts = line.split()
                if len(parts) >= 3 and parts[-1] == "_PyRuntime":
                    try:
                        py_runtime_offset = int(parts[0], 16)
                        break
                    except ValueError:
                        continue
            if py_runtime_offset is not None:
                break

        if py_runtime_offset is None:
            return None

        addr = libpython_base + py_runtime_offset
        print("[off_cpu] pid {} _PyRuntime address: 0x{:x}".format(pid, addr),
              file=sys.stderr)
        return addr

    def _refresh_container_tid_map(self):
        """Populate off_cpu_host_to_container_tid via /proc NSpid lines."""
        if self.bpf is None:
            return
        try:
            bpf_map = self.bpf["off_cpu_host_to_container_tid"]
        except KeyError:
            return
        for pid in self._target_pids:
            task_dir = "/proc/{}/task".format(pid)
            try:
                host_tids = os.listdir(task_dir)
            except (FileNotFoundError, PermissionError):
                continue
            for host_tid_str in host_tids:
                status_path = "{}/{}/status".format(task_dir, host_tid_str)
                try:
                    with open(status_path, "r") as f:
                        for line in f:
                            if line.startswith("NSpid:"):
                                parts = line.split()
                                if len(parts) >= 3:
                                    host_tid = int(parts[1])
                                    container_tid = int(parts[-1])
                                elif len(parts) == 2:
                                    host_tid = int(parts[1])
                                    container_tid = host_tid
                                else:
                                    break
                                try:
                                    bpf_map[ctypes.c_uint32(host_tid)] = \
                                        ctypes.c_uint32(container_tid)
                                except Exception:
                                    pass
                                break
                except (FileNotFoundError, PermissionError):
                    continue

    def _read_python_string(self, pid, addr):
        if not self._is_valid_user_addr(addr):
            return ""
        try:
            with open("/proc/{}/mem".format(pid), "rb") as mem:
                mem.seek(addr + PY311_OFFSETS["unicode_length"])
                length = struct.unpack("<Q", mem.read(8))[0]
                if length == 0 or length > 1024:
                    return ""
                mem.seek(addr + PY311_OFFSETS["unicode_data"])
                data = mem.read(min(length, 256))
                return data.decode("utf-8", errors="replace")
        except (OSError, struct.error, ValueError, OverflowError):
            return ""

    def _resolve_code(self, pid, code_addr):
        key = (pid, code_addr)
        cached = self._code_cache.get(key)
        if cached is not None:
            return cached
        if not self._is_valid_user_addr(code_addr):
            result = ("<unknown>", "<unknown>", 0)
            self._code_cache[key] = result
            return result
        try:
            with open("/proc/{}/mem".format(pid), "rb") as mem:
                mem.seek(code_addr + PY311_OFFSETS["code_co_name"])
                name_addr = struct.unpack("<Q", mem.read(8))[0]
                mem.seek(code_addr + PY311_OFFSETS["code_co_filename"])
                file_addr = struct.unpack("<Q", mem.read(8))[0]
                mem.seek(code_addr + PY311_OFFSETS["code_co_firstlineno"])
                lineno = struct.unpack("<i", mem.read(4))[0]
            func_name = self._read_python_string(pid, name_addr)
            filename = self._read_python_string(pid, file_addr)
            result = (func_name, filename, lineno)
        except (OSError, struct.error, ValueError, OverflowError):
            result = ("<unknown>", "<unknown>", 0)
        self._code_cache[key] = result
        return result

    def bpf_text(self):
        text = """
        #include <uapi/linux/ptrace.h>
        #include <linux/sched.h>

        #define PY_MAX_STACK_DEPTH 20

        #define RUNTIME_INTERPRETERS_OFFSET     OFFSET_RUNTIME_INTERPRETERS
        #define INTERPRETERS_HEAD_OFFSET        OFFSET_INTERPRETERS_HEAD
        #define ISTATE_THREADS_OFFSET           OFFSET_ISTATE_THREADS
        #define THREADS_HEAD_OFFSET             OFFSET_THREADS_HEAD
        #define TSTATE_NEXT_OFFSET              OFFSET_TSTATE_NEXT
        #define TSTATE_CFRAME_OFFSET            OFFSET_TSTATE_CFRAME
        #define TSTATE_NATIVE_TID_OFFSET        OFFSET_TSTATE_NATIVE_TID
        #define CFRAME_CURRENT_FRAME_OFFSET     OFFSET_CFRAME_CURRENT_FRAME
        #define IFRAME_F_CODE_OFFSET            OFFSET_IFRAME_F_CODE
        #define IFRAME_PREVIOUS_OFFSET          OFFSET_IFRAME_PREVIOUS

        BPF_HASH(off_cpu_start, u32, u64);
        BPF_HASH(off_cpu_state, u32, u64);
        BPF_HASH(off_cpu_kstack, u32, s32);
        BPF_HASH(off_cpu_ustack, u32, s32);
        BPF_HASH(runq_start, u32, u64);
        BPF_HASH(off_cpu_dur, u32, u64);

        BPF_STACK_TRACE(stack_traces, 16384);

        // Python stack capture: same pattern as PyStackProfilerTracker,
        // but keyed by the tid going off-CPU at sched_switch time.
        struct py_stack_t {
            u32 depth;
            u64 code_addrs[PY_MAX_STACK_DEPTH];
        };

        // Populated by userspace: target Python pids -> _PyRuntime address
        BPF_HASH(off_cpu_target_pid_to_runtime, u32, u64, 64);
        // Populated by userspace from /proc/<pid>/task/<tid>/status NSpid
        BPF_HASH(off_cpu_host_to_container_tid, u32, u32, 8192);
        // Per-tid Python stack captured at off-CPU, consumed at on-CPU
        BPF_HASH(off_cpu_py_stack, u32, struct py_stack_t, 10240);
        // Per-CPU scratch to build a py_stack_t without blowing the BPF stack
        BPF_PERCPU_ARRAY(off_cpu_py_scratch, struct py_stack_t, 1);

        struct event_t {
            u32 tid;
            u64 off_cpu_us;
            u64 runq_us;
            u64 start_ns;
            u64 end_ns;
            u64 prev_state;
            u32 cpu;
            char comm[16];
            s32 kstack_id;
            s32 ustack_id;
            u32 py_stack_depth;
            u64 py_code_addrs[PY_MAX_STACK_DEPTH];
        };

        BPF_PERF_OUTPUT(events);

        TRACEPOINT_PROBE(sched, sched_switch)
        {
            u64 now = bpf_ktime_get_ns();
            u32 prev_tid = args->prev_pid;
            u64 prev_state = (u64)args->prev_state;

            if (prev_state != 0 && prev_tid != 0) {
                off_cpu_start.update(&prev_tid, &now);
                off_cpu_state.update(&prev_tid, &prev_state);
                s32 kstack_id = stack_traces.get_stackid(args, 0);
                s32 ustack_id = stack_traces.get_stackid(args, BPF_F_USER_STACK);
                off_cpu_kstack.update(&prev_tid, &kstack_id);
                off_cpu_ustack.update(&prev_tid, &ustack_id);

                // ---- Python stack walk for outgoing thread ----
                // During sched_switch the current context is still prev, so
                // bpf_get_current_pid_tgid() gives us prev's (tgid, tid).
                u32 prev_tgid = bpf_get_current_pid_tgid() >> 32;
                u64 *py_runtime_p =
                    off_cpu_target_pid_to_runtime.lookup(&prev_tgid);
                if (py_runtime_p) {
                    u32 *container_tid_p =
                        off_cpu_host_to_container_tid.lookup(&prev_tid);
                    if (container_tid_p) {
                        u64 py_runtime_addr = *py_runtime_p;
                        u32 target_container_tid = *container_tid_p;

                        int zero = 0;
                        struct py_stack_t *pystk =
                            off_cpu_py_scratch.lookup(&zero);
                        if (pystk) {
                            __builtin_memset(pystk, 0, sizeof(*pystk));

                            u64 interp_addr = 0;
                            u64 interp_ptr_addr = py_runtime_addr +
                                RUNTIME_INTERPRETERS_OFFSET +
                                INTERPRETERS_HEAD_OFFSET;
                            if (bpf_probe_read(&interp_addr,
                                    sizeof(interp_addr),
                                    (void *)interp_ptr_addr) == 0
                                && interp_addr) {

                                u64 tstate_addr = 0;
                                u64 tstate_ptr_addr = interp_addr +
                                    ISTATE_THREADS_OFFSET +
                                    THREADS_HEAD_OFFSET;
                                if (bpf_probe_read(&tstate_addr,
                                        sizeof(tstate_addr),
                                        (void *)tstate_ptr_addr) == 0) {

                                    u64 native_tid = 0;
                                    u64 matched_tstate = 0;

                                    #define OC_CHECK_ONE_THREAD(idx) \
                                        if (!tstate_addr) goto oc_thread_done; \
                                        if (bpf_probe_read(&native_tid, \
                                                sizeof(native_tid), \
                                                (void *)(tstate_addr + \
                                                    TSTATE_NATIVE_TID_OFFSET)) != 0) \
                                            goto oc_thread_done; \
                                        if ((u32)native_tid == target_container_tid) { \
                                            matched_tstate = tstate_addr; \
                                            goto oc_thread_done; \
                                        } \
                                        { u64 next_t = 0; \
                                          if (bpf_probe_read(&next_t, \
                                                  sizeof(next_t), \
                                                  (void *)(tstate_addr + \
                                                      TSTATE_NEXT_OFFSET)) != 0) \
                                              goto oc_thread_done; \
                                          tstate_addr = next_t; }

                                    OC_CHECK_ONE_THREAD(0)  OC_CHECK_ONE_THREAD(1)
                                    OC_CHECK_ONE_THREAD(2)  OC_CHECK_ONE_THREAD(3)
                                    OC_CHECK_ONE_THREAD(4)  OC_CHECK_ONE_THREAD(5)
                                    OC_CHECK_ONE_THREAD(6)  OC_CHECK_ONE_THREAD(7)
                                    OC_CHECK_ONE_THREAD(8)  OC_CHECK_ONE_THREAD(9)
                                    OC_CHECK_ONE_THREAD(10) OC_CHECK_ONE_THREAD(11)
                                    OC_CHECK_ONE_THREAD(12) OC_CHECK_ONE_THREAD(13)
                                    OC_CHECK_ONE_THREAD(14) OC_CHECK_ONE_THREAD(15)
                                    OC_CHECK_ONE_THREAD(16) OC_CHECK_ONE_THREAD(17)
                                    OC_CHECK_ONE_THREAD(18) OC_CHECK_ONE_THREAD(19)
                                    OC_CHECK_ONE_THREAD(20) OC_CHECK_ONE_THREAD(21)
                                    OC_CHECK_ONE_THREAD(22) OC_CHECK_ONE_THREAD(23)
                                    OC_CHECK_ONE_THREAD(24) OC_CHECK_ONE_THREAD(25)
                                    OC_CHECK_ONE_THREAD(26) OC_CHECK_ONE_THREAD(27)
                                    OC_CHECK_ONE_THREAD(28) OC_CHECK_ONE_THREAD(29)
                                    OC_CHECK_ONE_THREAD(30) OC_CHECK_ONE_THREAD(31)

                                oc_thread_done:
                                    if (matched_tstate) {
                                        u64 cframe_addr = 0;
                                        if (bpf_probe_read(&cframe_addr,
                                                sizeof(cframe_addr),
                                                (void *)(matched_tstate +
                                                    TSTATE_CFRAME_OFFSET)) == 0
                                            && cframe_addr) {

                                            u64 frame_addr = 0;
                                            bpf_probe_read(&frame_addr,
                                                sizeof(frame_addr),
                                                (void *)(cframe_addr +
                                                    CFRAME_CURRENT_FRAME_OFFSET));

                                            u64 code_addr;
                                            u64 prev;

                                            #define OC_WALK_ONE_FRAME(idx) \
                                                if (!frame_addr) goto oc_frame_done; \
                                                code_addr = 0; \
                                                if (bpf_probe_read(&code_addr, \
                                                        sizeof(code_addr), \
                                                        (void *)(frame_addr + \
                                                            IFRAME_F_CODE_OFFSET)) != 0) \
                                                    goto oc_frame_done; \
                                                if (code_addr) { \
                                                    pystk->code_addrs[idx] = code_addr; \
                                                    pystk->depth = idx + 1; \
                                                } \
                                                prev = 0; \
                                                if (bpf_probe_read(&prev, sizeof(prev), \
                                                        (void *)(frame_addr + \
                                                            IFRAME_PREVIOUS_OFFSET)) != 0) \
                                                    goto oc_frame_done; \
                                                frame_addr = prev;

                                            OC_WALK_ONE_FRAME(0)  OC_WALK_ONE_FRAME(1)
                                            OC_WALK_ONE_FRAME(2)  OC_WALK_ONE_FRAME(3)
                                            OC_WALK_ONE_FRAME(4)  OC_WALK_ONE_FRAME(5)
                                            OC_WALK_ONE_FRAME(6)  OC_WALK_ONE_FRAME(7)
                                            OC_WALK_ONE_FRAME(8)  OC_WALK_ONE_FRAME(9)
                                            OC_WALK_ONE_FRAME(10) OC_WALK_ONE_FRAME(11)
                                            OC_WALK_ONE_FRAME(12) OC_WALK_ONE_FRAME(13)
                                            OC_WALK_ONE_FRAME(14) OC_WALK_ONE_FRAME(15)
                                            OC_WALK_ONE_FRAME(16) OC_WALK_ONE_FRAME(17)
                                            OC_WALK_ONE_FRAME(18) OC_WALK_ONE_FRAME(19)
                                        oc_frame_done:
                                            ;
                                        }
                                    }
                                }
                            }

                            if (pystk->depth > 0) {
                                off_cpu_py_stack.update(&prev_tid, pystk);
                            }
                        }
                    }
                }
                // ---- end Python stack walk ----
            }

            u32 next_tid = args->next_pid;
            if (next_tid == 0) return 0;

            u64 *runq_ts = runq_start.lookup(&next_tid);
            if (runq_ts == 0) return 0;

            u64 runq_us = (now - *runq_ts) / 1000;
            runq_start.delete(&next_tid);

            u64 *off_us = off_cpu_dur.lookup(&next_tid);
            u64 off_cpu_us = (off_us != 0) ? *off_us : 0;
            if (off_us != 0) off_cpu_dur.delete(&next_tid);

            u64 *state_p = off_cpu_state.lookup(&next_tid);
            u64 prev_st = (state_p != 0) ? *state_p : 0;
            if (state_p != 0) off_cpu_state.delete(&next_tid);

            s32 *kstack_p = off_cpu_kstack.lookup(&next_tid);
            s32 kstack = (kstack_p != 0) ? *kstack_p : -1;
            if (kstack_p != 0) off_cpu_kstack.delete(&next_tid);

            s32 *ustack_p = off_cpu_ustack.lookup(&next_tid);
            s32 ustack = (ustack_p != 0) ? *ustack_p : -1;
            if (ustack_p != 0) off_cpu_ustack.delete(&next_tid);

            // Lookup Python stack that was captured when this tid went off-CPU
            struct py_stack_t *pystk_p = off_cpu_py_stack.lookup(&next_tid);

            u64 total_us = off_cpu_us + runq_us;
            if (total_us < MIN_TOTAL_US) {
                // Still clean up the py_stack map entry so it doesn't leak
                if (pystk_p != 0) off_cpu_py_stack.delete(&next_tid);
                return 0;
            }

            struct event_t evt = {};
            evt.tid = next_tid;
            evt.off_cpu_us = off_cpu_us;
            evt.runq_us = runq_us;
            evt.start_ns = now - (total_us * 1000);
            evt.end_ns = now;
            evt.prev_state = prev_st;
            evt.cpu = bpf_get_smp_processor_id();
            evt.kstack_id = kstack;
            evt.ustack_id = ustack;
            if (pystk_p != 0) {
                evt.py_stack_depth = pystk_p->depth;
                __builtin_memcpy(&evt.py_code_addrs, pystk_p->code_addrs,
                                 sizeof(evt.py_code_addrs));
                off_cpu_py_stack.delete(&next_tid);
            }
            __builtin_memcpy(&evt.comm, args->next_comm, sizeof(evt.comm));

            events.perf_submit(args, &evt, sizeof(evt));
            return 0;
        }

        TRACEPOINT_PROBE(sched, sched_wakeup)
        {
            u64 now = bpf_ktime_get_ns();
            u32 tid = args->pid;

            u64 *off_ts = off_cpu_start.lookup(&tid);
            if (off_ts != 0) {
                u64 off_us = (now - *off_ts) / 1000;
                off_cpu_dur.update(&tid, &off_us);
                off_cpu_start.delete(&tid);
            }
            runq_start.update(&tid, &now);
            return 0;
        }

        TRACEPOINT_PROBE(sched, sched_wakeup_new)
        {
            u64 now = bpf_ktime_get_ns();
            u32 tid = args->pid;
            runq_start.update(&tid, &now);
            return 0;
        }
        """
        text = text.replace("MIN_TOTAL_US", str(self.min_total_us))
        # Substitute PY311 struct offsets (same as PyStackProfilerTracker)
        text = (text
            .replace("OFFSET_RUNTIME_INTERPRETERS", str(PY311_OFFSETS["runtime_interpreters"]))
            .replace("OFFSET_INTERPRETERS_HEAD", str(PY311_OFFSETS["interpreters_head"]))
            .replace("OFFSET_ISTATE_THREADS", str(PY311_OFFSETS["istate_threads"]))
            .replace("OFFSET_THREADS_HEAD", str(PY311_OFFSETS["threads_head"]))
            .replace("OFFSET_TSTATE_NEXT", str(PY311_OFFSETS["tstate_next"]))
            .replace("OFFSET_TSTATE_CFRAME", str(PY311_OFFSETS["tstate_cframe"]))
            .replace("OFFSET_TSTATE_NATIVE_TID", str(PY311_OFFSETS["tstate_native_thread_id"]))
            .replace("OFFSET_CFRAME_CURRENT_FRAME", str(PY311_OFFSETS["cframe_current_frame"]))
            .replace("OFFSET_IFRAME_F_CODE", str(PY311_OFFSETS["iframe_f_code"]))
            .replace("OFFSET_IFRAME_PREVIOUS", str(PY311_OFFSETS["iframe_previous"]))
        )
        return text

    def perf_buffer_name(self):
        return "events"

    def attach_probes(self, bpf):
        pass

    def setup(self):
        super(OffCPUStackTracker, self).setup()
        self.bpf[self.perf_buffer_name()].open_perf_buffer(
            self.safe_handle_event, page_cnt=512
        )

        if not self.py_enable:
            # Safety flag: py_stack disabled. BPF walk still compiled but
            # off_cpu_target_pid_to_runtime map stays empty -> BPF's null
            # check (`if (py_runtime_p)`) short-circuits the walk on every
            # sched_switch. Zero py stacks emitted. off_cpu itself still
            # runs normally (kernel+user stacks, timings, tid mapping).
            print("[off_cpu] python stack capture DISABLED "
                  "(--no-offcpu-py-enable)", file=sys.stderr)
            # Still start the tid refresher (used by base off_cpu tid
            # resolution, not just py_stack).
            self._refresher_thread = threading.Thread(
                target=self._refresher_loop, daemon=True)
            self._refresher_thread.start()
            print("[off_cpu] periodic tid refresh started (every {}s)".format(
                self._tid_refresh_interval), file=sys.stderr)
            return

        # Populate the pid -> _PyRuntime address map so BPF can walk the
        # Python thread state chain for target processes going off-CPU.
        # Non-Python pids or pids where _PyRuntime can't be found are simply
        # skipped (off-CPU still works, just without a Python stack).
        runtime_map = self.bpf["off_cpu_target_pid_to_runtime"]
        any_py_loaded = False
        for pid in self.pids:
            addr = self._find_py_runtime_addr(pid)
            if addr is None:
                continue
            try:
                runtime_map[ctypes.c_uint32(pid)] = ctypes.c_uint64(addr)
                any_py_loaded = True
            except Exception as ex:
                print("[off_cpu] failed to add pid {} to runtime map: {}".format(
                    pid, ex), file=sys.stderr)
        if any_py_loaded:
            # Prime the host->container tid map so early events have context
            self._refresh_container_tid_map()
            print("[off_cpu] python stack capture enabled", file=sys.stderr)
        else:
            print("[off_cpu] no python pids resolvable; py_stack will be empty",
                  file=sys.stderr)

        # Start periodic tid refresher so newly-spawned gthread workers
        # get added to the map without waiting for a miss.
        self._refresher_thread = threading.Thread(
            target=self._refresher_loop, daemon=True)
        self._refresher_thread.start()
        print("[off_cpu] periodic tid refresh started (every {}s)".format(
            self._tid_refresh_interval), file=sys.stderr)

    def _resolve_kstack(self, stack_id):
        if stack_id < 0:
            return []
        try:
            stack_traces = self.bpf.get_table("stack_traces")
            frames = []
            for addr in stack_traces.walk(stack_id):
                sym = self.bpf.ksym(addr, show_offset=False)
                if isinstance(sym, bytes):
                    sym = sym.decode('utf-8', errors='replace')
                frames.append(sym)
                if len(frames) >= self.max_stack_depth:
                    break
            return frames
        except Exception:
            return []

    def _resolve_ustack(self, stack_id, pid):
        if stack_id < 0 or pid == 0:
            return []
        try:
            stack_traces = self.bpf.get_table("stack_traces")
            frames = []
            for addr in stack_traces.walk(stack_id):
                sym = self.bpf.sym(addr, pid, show_module=True, show_offset=False)
                if isinstance(sym, bytes):
                    sym = sym.decode('utf-8', errors='replace')
                frames.append(sym)
                if len(frames) >= self.max_stack_depth:
                    break
            return frames
        except Exception:
            return []

    def handle_event(self, cpu, data, size):
        e = self.bpf["events"].event(data)
        pid = self._resolve_pid_for_tid(e.tid)
        if pid is None:
            return

        total_ms = round((e.off_cpu_us + e.runq_us) / 1000.0, 3)
        doc = self.base_doc(pid, e.tid, e.start_ns, e.end_ns, total_ms)
        doc["comm"] = decode_comm(e.comm)
        doc["thread_name"] = self.resolver.get(pid, e.tid)
        doc["off_cpu_ms"] = round(e.off_cpu_us / 1000.0, 3)
        doc["runq_ms"] = round(e.runq_us / 1000.0, 3)
        doc["prev_state"] = state_to_str(e.prev_state)
        doc["cpu"] = e.cpu
        doc["kernel_stack"] = self._resolve_kstack(e.kstack_id)
        doc["user_stack"] = self._resolve_ustack(e.ustack_id, pid)

        # Resolve Python stack captured at off-CPU time. Only include if
        # the event is big enough per py_min_ms (default 0 = always).
        py_stack_str = ""
        py_depth = int(e.py_stack_depth) if hasattr(e, "py_stack_depth") else 0
        if py_depth > 0 and total_ms >= self.py_min_ms:
            frames = []
            for i in range(py_depth):
                code_addr = e.py_code_addrs[i]
                if code_addr == 0:
                    continue
                func_name, filename, lineno = self._resolve_code(pid, code_addr)
                frames.append("{} ({}:{})".format(
                    func_name, filename or "?", lineno))
            # Root-first, matching PyStackProfilerTracker's convention
            py_stack_str = ";".join(reversed(frames))
        doc["py_stack"] = py_stack_str
        doc["py_stack_depth"] = py_depth
        self.emit(doc)


# =============================================================================
# Mutex lock tracker  (UNCHANGED — counter-only, no per-event docs)
# =============================================================================

class MutexLockTracker(BaseTracker):
    """Tracks total pthread_mutex_lock hold time in a BPF array.
    No perf_buffer events — counter polled by HandoffTracker periodic emitter."""

    METRIC_NAME = "mutex_lock"

    def bpf_text(self):
        text = """
        #include <uapi/linux/ptrace.h>

        struct lock_ts {
            u32 pid;
            u64 ts;
        };

        BPF_ARRAY(lock_time, u64, 1);
        BPF_HASH(lock_details, u32, struct lock_ts);

        int mutex_entry(struct pt_regs *ctx)
        {
            u32 pid = bpf_get_current_pid_tgid() >> 32;
            u32 tid = (u32)bpf_get_current_pid_tgid();
            FILTER_PID
            u64 ts = bpf_ktime_get_ns();
            struct lock_ts lock = {};
            lock.pid = pid;
            lock.ts = ts;
            lock_details.update(&tid, &lock);
            return 0;
        }

        int mutex_exit(struct pt_regs *ctx)
        {
            u32 pid = bpf_get_current_pid_tgid() >> 32;
            u32 tid = (u32)bpf_get_current_pid_tgid();
            FILTER_PID
            struct lock_ts *lock_obj = lock_details.lookup(&tid);
            if (lock_obj != NULL) {
                u64 curr_time = bpf_ktime_get_ns();
                u64 delta_us = (curr_time - lock_obj->ts) / 1000;
                lock_time.atomic_increment(0, delta_us);
                lock_details.delete(&tid);
            }
            return 0;
        }
        """
        return text.replace("FILTER_PID", self.pid_filter_clause())

    def perf_buffer_name(self):
        return None

    def attach_probes(self, bpf):
        first_pid = self.pids[0]
        candidates = [
            "/proc/{0}/root/lib/aarch64-linux-gnu/libpthread.so.0".format(first_pid),
            "/proc/{0}/root/lib/x86_64-linux-gnu/libpthread.so.0".format(first_pid),
            "/proc/{0}/root/usr/lib/x86_64-linux-gnu/libpthread.so.0".format(first_pid),
        ]
        attached = False
        for path in candidates:
            if os.path.exists(path):
                try:
                    bpf.attach_uprobe(name=path, sym="pthread_mutex_lock",
                                      fn_name="mutex_entry")
                    bpf.attach_uretprobe(name=path, sym="pthread_mutex_lock",
                                         fn_name="mutex_exit")
                    attached = True
                    print("[mutex_lock] attached to {}".format(path), file=sys.stderr)
                    break
                except Exception as ex:
                    print("[mutex_lock] failed attach to {}: {}".format(path, ex),
                          file=sys.stderr)
        if not attached:
            print("[mutex_lock] WARNING: could not attach pthread_mutex_lock uprobe; "
                  "lock_latency will be 0", file=sys.stderr)

    def handle_event(self, cpu, data, size):
        pass

    def get_and_clear_lock_time_us(self):
        if self.bpf is None:
            return 0
        try:
            val = self.bpf["lock_time"][c_int(0)].value
            self.bpf["lock_time"].clear()
            return val
        except Exception as ex:
            print("[mutex_lock] read error: {}".format(ex), file=sys.stderr)
            return 0


# =============================================================================
# Handoff tracker  (UNCHANGED logic; container ids added via base_doc + worker/main)
# =============================================================================

class HandoffTracker(BaseTracker):
    METRIC_NAME = "handoff"

    PATH_NAMES = {1: "accept", 2: "epoll_del"}
    PICKUP_NAMES = {1: "recvfrom", 2: "recvmsg"}

    def __init__(self, pids, env_name, machine_ip, resolver, comm_cache,
                 writer=None, also_stdout=False, min_handoff_ms=0.0,
                 mutex_tracker=None,
                 queue_size_interval=1.0, request_count_interval=15.0):
        super(HandoffTracker, self).__init__(
            pids, env_name, machine_ip, resolver, comm_cache,
            writer=writer, also_stdout=also_stdout)
        self.min_handoff_us = int(min_handoff_ms * 1000)
        self.mutex_tracker = mutex_tracker
        self.queue_size_interval = queue_size_interval
        self.request_count_interval = request_count_interval
        self._stop_emitter = False
        self._emitter_thread = None

        self._pid_fd_offsets = {}
        offset = 0
        for pid in self.pids:
            self._pid_fd_offsets[pid] = offset
            offset += 1500

    def _build_fd_setup_c(self):
        lines = []
        for pid, off in self._pid_fd_offsets.items():
            lines.append("if (pid == {pid}) {{ final_val = {off}; }}".format(
                pid=pid, off=off))
        return "\n            ".join(lines)

    def bpf_text(self):
        text = """
        #include <uapi/linux/ptrace.h>

        // ============================================================
        // EXISTING HANDOFF LOGIC (unchanged)
        // ============================================================
        #define PATH_ACCEPT 1
        #define PATH_EPOLL  2

        struct queue_info_t {
            u64 ts_queued;
            u32 main_tid;
            u8  path;
        };

        BPF_HASH(queued_fds, u64, struct queue_info_t);

        struct handoff_event_t {
            u32 pid;
            u32 main_tid;
            u32 worker_tid;
            s32 fd;
            u64 ts_queued;
            u64 ts_pickup;
            u64 handoff_us;
            u8  path;
            u8  pickup_via;
            char worker_comm[16];
        };

        BPF_PERF_OUTPUT(handoff_events);

        static __always_inline u64 fd_key(u32 pid, s32 fd) {
            return ((u64)pid << 32) | (u32)fd;
        }

        // ============================================================
        // REQUEST-QUEUE MAPS (counters polled periodically by Python)
        // ============================================================
        BPF_ARRAY(rq_fd_counts, u64, 8000);
        BPF_ARRAY(rq_request_queued, u64, 1);
        BPF_ARRAY(rq_threads_used, u64, 100000);
        BPF_ARRAY(rq_total_request, u64, 1);
        BPF_ARRAY(rq_epoll_fd, u64, 8000);
        BPF_ARRAY(rq_fd_request_ts, u64, 8000);
        BPF_ARRAY(rq_total_time, u64, 1);
        BPF_ARRAY(rq_connection_accepted_fd, u64, 8000);

        TRACEPOINT_PROBE(syscalls, sys_exit_accept4)
        {
            u32 pid = bpf_get_current_pid_tgid() >> 32;
            u32 tid = (u32)bpf_get_current_pid_tgid();
            FILTER_PID

            s32 fd = args->ret;
            if (fd < 0) return 0;

            u64 key = fd_key(pid, fd);
            struct queue_info_t info = {};
            info.ts_queued = bpf_ktime_get_ns();
            info.main_tid = tid;
            info.path = PATH_ACCEPT;
            queued_fds.update(&key, &info);

            int final_val = 0;
            FD_SETUP
            int final_fd_key = final_val + fd;
            u64 fd_val = 1;
            rq_fd_counts.update(&final_fd_key, &fd_val);

            int conn_key = final_val + fd;
            u64 conn_val = 1;
            rq_connection_accepted_fd.update(&conn_key, &conn_val);

            return 0;
        }

        TRACEPOINT_PROBE(syscalls, sys_enter_epoll_ctl)
        {
            u32 pid = bpf_get_current_pid_tgid() >> 32;
            u32 tid = (u32)bpf_get_current_pid_tgid();
            FILTER_PID

            int op = args->op;
            s32 fd = args->fd;
            if (fd < 0) return 0;

            if (op == 2) {
                u64 key = fd_key(pid, fd);
                struct queue_info_t info = {};
                info.ts_queued = bpf_ktime_get_ns();
                info.main_tid = tid;
                info.path = PATH_EPOLL;
                queued_fds.update(&key, &info);
            }

            if (op == 2) {
                int final_val = 0;
                FD_SETUP
                int final_epoll_key = final_val + fd;
                u64 epoll_val = 1;
                rq_epoll_fd.update(&final_epoll_key, &epoll_val);
            }

            return 0;
        }

        TRACEPOINT_PROBE(syscalls, sys_enter_ioctl)
        {
            u32 pid = bpf_get_current_pid_tgid() >> 32;
            u32 tid = (u32)bpf_get_current_pid_tgid();
            FILTER_PID

            s32 fd = args->fd;
            if (fd < 0) return 0;

            int final_val = 0;
            FD_SETUP
            int final_ioctl_key = final_val + fd;
            u64 *ioctl_addr = rq_epoll_fd.lookup(&final_ioctl_key);

            int final_fd_key = final_val + fd;
            u64 fd_val = 1;
            int conn_key = final_val + fd;

            if (ioctl_addr != NULL && *ioctl_addr == 1 && args->cmd == 21537) {
                u64 *current_val = rq_connection_accepted_fd.lookup(&conn_key);
                u64 new_val = (current_val != NULL) ? (*current_val + 1) : 1;
                rq_connection_accepted_fd.update(&conn_key, &new_val);
                rq_fd_counts.update(&final_fd_key, &fd_val);
                rq_request_queued.atomic_increment(0);
            }
            return 0;
        }

        TRACEPOINT_PROBE(syscalls, sys_enter_recvfrom)
        {
            u32 pid = bpf_get_current_pid_tgid() >> 32;
            u32 tid = (u32)bpf_get_current_pid_tgid();
            FILTER_PID

            s32 fd = args->fd;
            if (fd < 0) return 0;

            u64 key = fd_key(pid, fd);
            struct queue_info_t *info = queued_fds.lookup(&key);
            if (info != NULL) {
                u64 now = bpf_ktime_get_ns();
                u64 handoff_us = (now - info->ts_queued) / 1000;

                if (handoff_us >= MIN_HANDOFF_US) {
                    struct handoff_event_t evt = {};
                    evt.pid = pid;
                    evt.main_tid = info->main_tid;
                    evt.worker_tid = tid;
                    evt.fd = fd;
                    evt.ts_queued = info->ts_queued;
                    evt.ts_pickup = now;
                    evt.handoff_us = handoff_us;
                    evt.path = info->path;
                    evt.pickup_via = 1;
                    bpf_get_current_comm(&evt.worker_comm, sizeof(evt.worker_comm));
                    handoff_events.perf_submit(args, &evt, sizeof(evt));
                }
                queued_fds.delete(&key);
            }

            int final_val = 0;
            FD_SETUP
            int final_fd_key = final_val + fd;
            int fd_request_final_key = final_val + fd;
            int final_epoll_key = final_val + fd;
            int conn_key = final_val + fd;

            u64* conn_addr = rq_connection_accepted_fd.lookup(&conn_key);
            u64 thread_val = 1;
            int zero_key = 0;
            rq_threads_used.update(&tid, &thread_val);

            if (conn_addr != NULL && *conn_addr > 0) {
                u64 epoll_val = 0;
                rq_epoll_fd.update(&final_epoll_key, &epoll_val);

                u64 new_val = *conn_addr - 1;
                rq_connection_accepted_fd.update(&conn_key, &new_val);

                u64 *current_count = rq_request_queued.lookup(&zero_key);
                if (current_count != NULL && *current_count > 0) {
                    rq_request_queued.atomic_increment(0, -1);
                }

                u64 *last_sendto_ts = rq_fd_request_ts.lookup(&fd_request_final_key);
                if (last_sendto_ts != NULL && *last_sendto_ts > 0) {
                    u64 api_latency = (bpf_ktime_get_ns() - *last_sendto_ts) / 1000;
                    rq_total_time.atomic_increment(0, api_latency);
                    u64 zero = 0;
                    rq_fd_request_ts.update(&fd_request_final_key, &zero);
                }

                rq_total_request.atomic_increment(0);
            }

            return 0;
        }

        TRACEPOINT_PROBE(syscalls, sys_enter_recvmsg)
        {
            u32 pid = bpf_get_current_pid_tgid() >> 32;
            u32 tid = (u32)bpf_get_current_pid_tgid();
            FILTER_PID

            s32 fd = args->fd;
            if (fd < 0) return 0;

            u64 key = fd_key(pid, fd);
            struct queue_info_t *info = queued_fds.lookup(&key);
            if (info == NULL) return 0;

            u64 now = bpf_ktime_get_ns();
            u64 handoff_us = (now - info->ts_queued) / 1000;

            if (handoff_us >= MIN_HANDOFF_US) {
                struct handoff_event_t evt = {};
                evt.pid = pid;
                evt.main_tid = info->main_tid;
                evt.worker_tid = tid;
                evt.fd = fd;
                evt.ts_queued = info->ts_queued;
                evt.ts_pickup = now;
                evt.handoff_us = handoff_us;
                evt.path = info->path;
                evt.pickup_via = 2;
                bpf_get_current_comm(&evt.worker_comm, sizeof(evt.worker_comm));
                handoff_events.perf_submit(args, &evt, sizeof(evt));
            }

            queued_fds.delete(&key);
            return 0;
        }

        TRACEPOINT_PROBE(syscalls, sys_enter_sendto)
        {
            u32 pid = bpf_get_current_pid_tgid() >> 32;
            FILTER_PID

            s32 fd = args->fd;
            if (fd < 0) return 0;

            int final_val = 0;
            FD_SETUP
            int fd_request_final_key = final_val + fd;

            u64 now = bpf_ktime_get_ns();
            rq_fd_request_ts.update(&fd_request_final_key, &now);
            return 0;
        }

        TRACEPOINT_PROBE(syscalls, sys_enter_close)
        {
            u32 pid = bpf_get_current_pid_tgid() >> 32;
            u32 tid = (u32)bpf_get_current_pid_tgid();
            FILTER_PID

            s32 fd = args->fd;
            if (fd < 0) return 0;

            u64 key = fd_key(pid, fd);
            queued_fds.delete(&key);

            int final_val = 0;
            FD_SETUP
            int conn_key = final_val + fd;

            u64* conn_addr = rq_connection_accepted_fd.lookup(&conn_key);
            if (conn_addr != NULL && *conn_addr > 0) {
                int zero_key = 0;
                u64 pending = *conn_addr;
                u64 *current_count = rq_request_queued.lookup(&zero_key);
                if (current_count != NULL && *current_count >= pending) {
                    rq_request_queued.atomic_increment(0, -pending);
                }
            }

            int final_fd_key = final_val + fd;
            int final_epoll_key = final_val + fd;
            int fd_request_final_key = final_val + fd;

            u64 zero64 = 0;
            rq_epoll_fd.update(&final_epoll_key, &zero64);
            rq_fd_counts.update(&final_fd_key, &zero64);
            rq_fd_request_ts.delete(&fd_request_final_key);
            rq_connection_accepted_fd.update(&conn_key, &zero64);

            return 0;
        }
        """
        text = text.replace("FILTER_PID", self.pid_filter_clause())
        text = text.replace("MIN_HANDOFF_US", str(self.min_handoff_us))
        text = text.replace("FD_SETUP", self._build_fd_setup_c())
        return text

    def perf_buffer_name(self):
        return "handoff_events"

    def handle_event(self, cpu, data, size):
        e = self.bpf["handoff_events"].event(data)
        handoff_ms = round(e.handoff_us / 1000.0, 3)

        # base_doc uses worker_tid as the canonical tid (existing behavior).
        # That gives doc["tid"] = worker_tid and doc["container_tid"] = container worker tid.
        doc = self.base_doc(e.pid, e.worker_tid, e.ts_queued, e.ts_pickup,
                            handoff_ms)
        doc["worker_tid"] = e.worker_tid
        doc["worker_comm"] = decode_comm(e.worker_comm)
        doc["worker_thread_name"] = self.resolver.get(e.pid, e.worker_tid)
        doc["main_tid"] = e.main_tid
        doc["main_comm"] = self.comm_cache.get(e.pid, e.main_tid)
        doc["main_thread_name"] = self.resolver.get(e.pid, e.main_tid)

        # Container-view IDs for both worker and main threads
        _, worker_container_tid = self.resolver.get_container_ids(
            e.pid, e.worker_tid)
        _, main_container_tid = self.resolver.get_container_ids(
            e.pid, e.main_tid)
        doc["worker_container_tid"] = worker_container_tid
        doc["main_container_tid"] = main_container_tid

        doc["fd"] = e.fd
        doc["queue_path"] = self.PATH_NAMES.get(e.path, "unknown")
        doc["pickup_via"] = self.PICKUP_NAMES.get(e.pickup_via, "unknown")
        doc["queued_time"] = ktime_to_iso(e.ts_queued)
        doc["pickup_time"] = ktime_to_iso(e.ts_pickup)
        doc["handoff_ms"] = handoff_ms
        self.emit(doc)

    # =========================================================================
    # Periodic emitter for request-queue ES metrics (UNCHANGED)
    # =========================================================================

    def start_periodic_emitter(self):
        self._emitter_thread = threading.Thread(
            target=self._periodic_emitter_loop, daemon=True)
        self._emitter_thread.start()
        print("[handoff] periodic emitter started "
              "(queue_size every {}s, request_count every {}s)".format(
                  self.queue_size_interval, self.request_count_interval),
              file=sys.stderr)

    def _periodic_emitter_loop(self):
        last_request_count_emit = time.time()
        time.sleep(0.5)

        while not self._stop_emitter:
            try:
                self._emit_queue_size()
            except Exception as ex:
                print("[handoff emitter] queue_size error: {}".format(ex),
                      file=sys.stderr)
                traceback.print_exc(file=sys.stderr)

            now = time.time()
            if now - last_request_count_emit >= self.request_count_interval:
                try:
                    self._emit_request_count_and_thread_pool()
                except Exception as ex:
                    print("[handoff emitter] request_count error: {}".format(ex),
                          file=sys.stderr)
                    traceback.print_exc(file=sys.stderr)
                last_request_count_emit = now

            time.sleep(self.queue_size_interval)

    def _emit_queue_size(self):
        if self.bpf is None:
            return
        try:
            request_count = self.bpf["rq_request_queued"][c_int(0)].value
        except Exception:
            return
        doc = {
            "metric": "request_queue_size",
            "server_name": self.env_name,
            "machine ip": self.machine_ip,
            "published_date": now_iso_es(),
            "request_queued": request_count,
        }
        if self.writer is not None:
            self.writer.enqueue(doc)
        if self.also_stdout or self.writer is None:
            print(json.dumps(doc))
            sys.stdout.flush()

    def _emit_request_count_and_thread_pool(self):
        if self.bpf is None:
            return

        try:
            total_request_raw = self.bpf["rq_total_request"][c_int(0)].value
            total_time_raw = self.bpf["rq_total_time"][c_int(0)].value
        except Exception as ex:
            print("[handoff emitter] read total error: {}".format(ex),
                  file=sys.stderr)
            return

        threads_used = 0
        try:
            threads_table = self.bpf["rq_threads_used"]
            counter = 0
            while counter < 100000:
                threads_used += threads_table[c_int(counter)].value
                counter += 1
        except Exception as ex:
            print("[handoff emitter] read threads_used error: {}".format(ex),
                  file=sys.stderr)

        total_lock_us = 0
        if self.mutex_tracker is not None:
            total_lock_us = self.mutex_tracker.get_and_clear_lock_time_us()
        total_lock_ms = float(total_lock_us) / 1000.0

        if total_request_raw != 0:
            avg_us = float(total_time_raw) / total_request_raw
            avg_ms = avg_us / 1000.0
        else:
            avg_ms = 0.0

        try:
            self.bpf["rq_total_request"].clear()
            self.bpf["rq_threads_used"].clear()
            self.bpf["rq_total_time"].clear()
        except Exception as ex:
            print("[handoff emitter] clear error: {}".format(ex), file=sys.stderr)

        thread_doc = {
            "metric": "thread_pool_utilisation",
            "server_name": self.env_name,
            "machine ip": self.machine_ip,
            "published_date": now_iso_es(),
            "threads_used": threads_used,
        }
        if self.writer is not None:
            self.writer.enqueue(thread_doc)
        if self.also_stdout or self.writer is None:
            print(json.dumps(thread_doc))

        request_doc = {
            "metric": "request_count",
            "server_name": self.env_name,
            "machine ip": self.machine_ip,
            "published_date": now_iso_es(),
            "total_request": total_request_raw,
            "total_time": avg_ms,
            "lock_latency": total_lock_ms,
        }
        if self.writer is not None:
            self.writer.enqueue(request_doc)
        if self.also_stdout or self.writer is None:
            print(json.dumps(request_doc))
            sys.stdout.flush()

    def stop(self):
        self._stop_emitter = True


# =============================================================================
# Python stack profiler tracker  (Pyroscope-style continuous CPU profiler)
#
# Samples Python stacks via perf_event hardware CPU cycles, walks PyThreadState
# frame chain in eBPF, resolves PyCodeObject pointers to function names in
# userspace, ships samples to ClickHouse table ebpf_py_stacks.
#
# Supports multiple PIDs — one eBPF program iterates a pid->py_runtime_addr
# hash map to find which target process is running.
# =============================================================================

PY311_OFFSETS = {
    "runtime_interpreters": 32,
    "interpreters_head": 8,
    "istate_threads": 8,
    "threads_head": 8,
    "tstate_next": 8,
    "tstate_cframe": 56,
    "tstate_native_thread_id": 160,
    "cframe_current_frame": 8,
    "iframe_f_code": 32,
    "iframe_previous": 48,
    "code_co_name": 120,
    "code_co_filename": 112,
    "code_co_firstlineno": 72,
    "unicode_length": 16,
    "unicode_data": 48,
}


PY_PROFILER_BPF_PROGRAM = r"""
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>

#define MAX_STACK_DEPTH 20

#define RUNTIME_INTERPRETERS_OFFSET     OFFSET_RUNTIME_INTERPRETERS
#define INTERPRETERS_HEAD_OFFSET        OFFSET_INTERPRETERS_HEAD
#define ISTATE_THREADS_OFFSET           OFFSET_ISTATE_THREADS
#define THREADS_HEAD_OFFSET             OFFSET_THREADS_HEAD
#define TSTATE_NEXT_OFFSET              OFFSET_TSTATE_NEXT
#define TSTATE_CFRAME_OFFSET            OFFSET_TSTATE_CFRAME
#define TSTATE_NATIVE_TID_OFFSET        OFFSET_TSTATE_NATIVE_TID
#define CFRAME_CURRENT_FRAME_OFFSET     OFFSET_CFRAME_CURRENT_FRAME
#define IFRAME_F_CODE_OFFSET            OFFSET_IFRAME_F_CODE
#define IFRAME_PREVIOUS_OFFSET          OFFSET_IFRAME_PREVIOUS

struct py_sample_t {
    u32 pid;
    u32 host_tid;
    u32 container_tid;
    u64 ts;
    u32 stack_depth;
    u64 code_addrs[MAX_STACK_DEPTH];
};

// pid -> _PyRuntime address (populated by userspace per target PID)
BPF_HASH(target_pid_to_runtime, u32, u64, 64);

// host_tid -> container_tid (populated by userspace from /proc NSpid)
BPF_HASH(host_to_container_tid, u32, u32, 4096);

BPF_PERF_OUTPUT(py_samples);
BPF_PERCPU_ARRAY(scratch, struct py_sample_t, 1);

int on_perf_event(struct bpf_perf_event_data *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;

    // Look up our _PyRuntime address for this PID (returns NULL if not a target)
    u64 *py_runtime_p = target_pid_to_runtime.lookup(&pid);
    if (!py_runtime_p) return 0;
    u64 py_runtime_addr = *py_runtime_p;

    u32 host_tid = (u32)bpf_get_current_pid_tgid();

    u32 *container_tid_p = host_to_container_tid.lookup(&host_tid);
    if (!container_tid_p) return 0;
    u32 target_container_tid = *container_tid_p;

    int zero = 0;
    struct py_sample_t *sample = scratch.lookup(&zero);
    if (!sample) return 0;

    __builtin_memset(sample, 0, sizeof(*sample));
    sample->pid = pid;
    sample->host_tid = host_tid;
    sample->container_tid = target_container_tid;
    sample->ts = bpf_ktime_get_ns();

    // Step 1: read interpreters.head
    u64 interp_addr = 0;
    u64 interp_ptr_addr = py_runtime_addr + RUNTIME_INTERPRETERS_OFFSET +
                          INTERPRETERS_HEAD_OFFSET;
    if (bpf_probe_read(&interp_addr, sizeof(interp_addr),
                             (void *)interp_ptr_addr) != 0) return 0;
    if (!interp_addr) return 0;

    // Step 2: read threads.head
    u64 tstate_addr = 0;
    u64 tstate_ptr_addr = interp_addr + ISTATE_THREADS_OFFSET + THREADS_HEAD_OFFSET;
    if (bpf_probe_read(&tstate_addr, sizeof(tstate_addr),
                             (void *)tstate_ptr_addr) != 0) return 0;

    // Step 3: walk thread list, find one with native_thread_id == target_container_tid
    u64 native_tid = 0;
    u64 matched_tstate = 0;

    #define CHECK_ONE_THREAD(idx) \
        if (!tstate_addr) goto thread_search_done; \
        if (bpf_probe_read(&native_tid, sizeof(native_tid), \
                                 (void *)(tstate_addr + TSTATE_NATIVE_TID_OFFSET)) != 0) \
            goto thread_search_done; \
        if ((u32)native_tid == target_container_tid) { \
            matched_tstate = tstate_addr; \
            goto thread_search_done; \
        } \
        { u64 next_t = 0; \
          if (bpf_probe_read(&next_t, sizeof(next_t), \
                                   (void *)(tstate_addr + TSTATE_NEXT_OFFSET)) != 0) \
              goto thread_search_done; \
          tstate_addr = next_t; }

    CHECK_ONE_THREAD(0) CHECK_ONE_THREAD(1) CHECK_ONE_THREAD(2) CHECK_ONE_THREAD(3)
    CHECK_ONE_THREAD(4) CHECK_ONE_THREAD(5) CHECK_ONE_THREAD(6) CHECK_ONE_THREAD(7)
    CHECK_ONE_THREAD(8) CHECK_ONE_THREAD(9) CHECK_ONE_THREAD(10) CHECK_ONE_THREAD(11)
    CHECK_ONE_THREAD(12) CHECK_ONE_THREAD(13) CHECK_ONE_THREAD(14) CHECK_ONE_THREAD(15)
    CHECK_ONE_THREAD(16) CHECK_ONE_THREAD(17) CHECK_ONE_THREAD(18) CHECK_ONE_THREAD(19)
    CHECK_ONE_THREAD(20) CHECK_ONE_THREAD(21) CHECK_ONE_THREAD(22) CHECK_ONE_THREAD(23)
    CHECK_ONE_THREAD(24) CHECK_ONE_THREAD(25) CHECK_ONE_THREAD(26) CHECK_ONE_THREAD(27)
    CHECK_ONE_THREAD(28) CHECK_ONE_THREAD(29) CHECK_ONE_THREAD(30) CHECK_ONE_THREAD(31)

thread_search_done:
    if (!matched_tstate) return 0;

    u64 cframe_addr = 0;
    if (bpf_probe_read(&cframe_addr, sizeof(cframe_addr),
                             (void *)(matched_tstate + TSTATE_CFRAME_OFFSET)) != 0) return 0;
    if (!cframe_addr) return 0;

    u64 frame_addr = 0;
    if (bpf_probe_read(&frame_addr, sizeof(frame_addr),
                             (void *)(cframe_addr + CFRAME_CURRENT_FRAME_OFFSET)) != 0) return 0;

    u64 code_addr;
    u64 prev;

    #define WALK_ONE_FRAME(idx) \
        if (!frame_addr) goto done; \
        code_addr = 0; \
        if (bpf_probe_read(&code_addr, sizeof(code_addr), \
                                (void *)(frame_addr + IFRAME_F_CODE_OFFSET)) != 0) \
            goto done; \
        if (code_addr) { \
            sample->code_addrs[idx] = code_addr; \
            sample->stack_depth = idx + 1; \
        } \
        prev = 0; \
        if (bpf_probe_read(&prev, sizeof(prev), \
                                (void *)(frame_addr + IFRAME_PREVIOUS_OFFSET)) != 0) \
            goto done; \
        frame_addr = prev;

    WALK_ONE_FRAME(0) WALK_ONE_FRAME(1) WALK_ONE_FRAME(2) WALK_ONE_FRAME(3)
    WALK_ONE_FRAME(4) WALK_ONE_FRAME(5) WALK_ONE_FRAME(6) WALK_ONE_FRAME(7)
    WALK_ONE_FRAME(8) WALK_ONE_FRAME(9) WALK_ONE_FRAME(10) WALK_ONE_FRAME(11)
    WALK_ONE_FRAME(12) WALK_ONE_FRAME(13) WALK_ONE_FRAME(14) WALK_ONE_FRAME(15)
    WALK_ONE_FRAME(16) WALK_ONE_FRAME(17) WALK_ONE_FRAME(18) WALK_ONE_FRAME(19)

done:
    if (sample->stack_depth > 0) {
        py_samples.perf_submit(ctx, sample, sizeof(*sample));
    }
    return 0;
}
"""


class PyStackProfilerTracker(BaseTracker):
    """Continuous Python CPU profiler. Samples PyThreadState frame chain
    at `frequency` Hz across all target PIDs via perf_event HARDWARE CPU_CYCLES.
    Emits one row per sample to ClickHouse table ebpf_py_stacks.

    Differs from other trackers:
      - Uses attach_perf_event (timer-based), not uprobe/tracepoint
      - Doesn't use the BaseTracker pid_filter (we filter via BPF hash lookup
        so we can support multiple PIDs with different _PyRuntime addrs)
      - Does its own setup() override
    """

    METRIC_NAME = "py_stack"

    def __init__(self, pids, env_name, machine_ip, resolver, comm_cache,
                 writer=None, also_stdout=False,
                 frequency=99, tid_refresh_interval=10.0):
        super(PyStackProfilerTracker, self).__init__(
            pids, env_name, machine_ip, resolver, comm_cache,
            writer=writer, also_stdout=also_stdout)
        self.frequency = frequency
        self.tid_refresh_interval = tid_refresh_interval
        # cache: code_addr -> (func_name, filename, lineno)
        # Each code_addr is per-pid (different processes have separate libpython
        # address spaces), so key by (pid, code_addr).
        self.code_cache = {}
        self._last_tid_refresh = 0
        self._refresher_stop = False
        self._refresher_thread = None

    def perf_buffer_name(self):
        return "py_samples"

    def _find_py_runtime_addr(self, pid):
        """Locate _PyRuntime address in the target process's address space."""
        libpython_base = None
        libpython_container_path = None
        try:
            with open("/proc/{}/maps".format(pid)) as f:
                for line in f:
                    if "libpython3.11" in line or "/python3.11" in line:
                        parts = line.split()
                        if "r-xp" in parts[1] or "r--p" in parts[1]:
                            addr_range = parts[0].split("-")
                            libpython_base = int(addr_range[0], 16)
                            libpython_container_path = parts[-1]
                            break

            if not libpython_base:
                with open("/proc/{}/maps".format(pid)) as f:
                    first_line = f.readline()
                    parts = first_line.split()
                    libpython_base = int(parts[0].split("-")[0], 16)
                    libpython_container_path = parts[-1]
        except (FileNotFoundError, PermissionError) as ex:
            print("[py_stack] cannot read /proc/{}/maps: {}".format(pid, ex),
                  file=sys.stderr)
            return None

        libpython_host_path = "/proc/{}/root{}".format(pid, libpython_container_path)
        if not os.path.exists(libpython_host_path):
            libpython_host_path = libpython_container_path

        py_runtime_offset = None
        for nm_args in (["nm", "-D", libpython_host_path],
                        ["nm", libpython_host_path]):
            try:
                result = subprocess.run(nm_args, capture_output=True,
                                        text=True, check=False)
            except FileNotFoundError:
                print("[py_stack] nm not found", file=sys.stderr)
                return None
            for line in result.stdout.splitlines():
                parts = line.split()
                if len(parts) >= 3 and parts[-1] == "_PyRuntime":
                    try:
                        py_runtime_offset = int(parts[0], 16)
                        break
                    except ValueError:
                        continue
            if py_runtime_offset is not None:
                break

        if py_runtime_offset is None:
            print("[py_stack] _PyRuntime not found for pid {}".format(pid),
                  file=sys.stderr)
            return None

        addr = libpython_base + py_runtime_offset
        print("[py_stack] pid {} _PyRuntime address: 0x{:x}".format(pid, addr),
              file=sys.stderr)
        return addr

    def _refresh_tid_map(self):
        """Read /proc/<pid>/task/<tid>/status NSpid lines for all target PIDs,
        populate the BPF host_to_container_tid hash."""
        if self.bpf is None:
            return
        bpf_map = self.bpf["host_to_container_tid"]
        total = 0
        for pid in self.pids:
            task_dir = "/proc/{}/task".format(pid)
            try:
                host_tids = os.listdir(task_dir)
            except (FileNotFoundError, PermissionError):
                continue
            for host_tid_str in host_tids:
                status_path = "{}/{}/status".format(task_dir, host_tid_str)
                try:
                    with open(status_path, "r") as f:
                        for line in f:
                            if line.startswith("NSpid:"):
                                parts = line.split()
                                if len(parts) >= 3:
                                    host_tid = int(parts[1])
                                    container_tid = int(parts[-1])
                                elif len(parts) == 2:
                                    host_tid = int(parts[1])
                                    container_tid = host_tid
                                else:
                                    break
                                try:
                                    bpf_map[ctypes.c_uint32(host_tid)] = \
                                        ctypes.c_uint32(container_tid)
                                    total += 1
                                except Exception:
                                    pass
                                break
                except (FileNotFoundError, PermissionError):
                    continue
        self._last_tid_refresh = time.time()

    def _refresher_loop(self):
        while not self._refresher_stop:
            time.sleep(self.tid_refresh_interval)
            try:
                self._refresh_tid_map()
            except Exception as ex:
                print("[py_stack] tid refresh error: {}".format(ex),
                      file=sys.stderr)

    # Userspace addresses on 64-bit Linux fit in 48 bits (canonical form).
    # Anything beyond 0x0000ffffffffffff is either kernel space or garbage
    # (corrupt read, race condition). off_t in /proc/<pid>/mem is signed,
    # so addresses with the high bit set cause seek() to overflow.
    _MAX_USER_ADDR = 0x0000ffffffffffff

    @classmethod
    def _is_valid_user_addr(cls, addr):
        return 0 < addr <= cls._MAX_USER_ADDR

    def _read_python_string(self, pid, addr):
        if not self._is_valid_user_addr(addr):
            return ""
        try:
            with open("/proc/{}/mem".format(pid), "rb") as mem:
                mem.seek(addr + PY311_OFFSETS["unicode_length"])
                length = struct.unpack("<Q", mem.read(8))[0]
                if length == 0 or length > 1024:
                    return ""
                mem.seek(addr + PY311_OFFSETS["unicode_data"])
                data = mem.read(min(length, 256))
                return data.decode("utf-8", errors="replace")
        except (OSError, struct.error, ValueError, OverflowError):
            return ""

    def _resolve_code(self, pid, code_addr):
        key = (pid, code_addr)
        if key in self.code_cache:
            return self.code_cache[key]
        if not self._is_valid_user_addr(code_addr):
            result = ("<unknown>", "<unknown>", 0)
            self.code_cache[key] = result
            return result
        try:
            with open("/proc/{}/mem".format(pid), "rb") as mem:
                mem.seek(code_addr + PY311_OFFSETS["code_co_name"])
                name_addr = struct.unpack("<Q", mem.read(8))[0]
                mem.seek(code_addr + PY311_OFFSETS["code_co_filename"])
                file_addr = struct.unpack("<Q", mem.read(8))[0]
                mem.seek(code_addr + PY311_OFFSETS["code_co_firstlineno"])
                lineno = struct.unpack("<i", mem.read(4))[0]
            func_name = self._read_python_string(pid, name_addr)
            filename = self._read_python_string(pid, file_addr)
            result = (func_name, filename, lineno)
        except (OSError, struct.error, ValueError, OverflowError):
            result = ("<unknown>", "<unknown>", 0)
        self.code_cache[key] = result
        return result

    def bpf_text(self):
        return (PY_PROFILER_BPF_PROGRAM
            .replace("OFFSET_RUNTIME_INTERPRETERS", str(PY311_OFFSETS["runtime_interpreters"]))
            .replace("OFFSET_INTERPRETERS_HEAD", str(PY311_OFFSETS["interpreters_head"]))
            .replace("OFFSET_ISTATE_THREADS", str(PY311_OFFSETS["istate_threads"]))
            .replace("OFFSET_THREADS_HEAD", str(PY311_OFFSETS["threads_head"]))
            .replace("OFFSET_TSTATE_NEXT", str(PY311_OFFSETS["tstate_next"]))
            .replace("OFFSET_TSTATE_CFRAME", str(PY311_OFFSETS["tstate_cframe"]))
            .replace("OFFSET_TSTATE_NATIVE_TID", str(PY311_OFFSETS["tstate_native_thread_id"]))
            .replace("OFFSET_CFRAME_CURRENT_FRAME", str(PY311_OFFSETS["cframe_current_frame"]))
            .replace("OFFSET_IFRAME_F_CODE", str(PY311_OFFSETS["iframe_f_code"]))
            .replace("OFFSET_IFRAME_PREVIOUS", str(PY311_OFFSETS["iframe_previous"]))
        )

    def setup(self):
        # Build BPF program from template
        text = self.bpf_text()
        self.bpf = BPF(text=text)

        # Populate the pid -> py_runtime_addr map
        runtime_map = self.bpf["target_pid_to_runtime"]
        any_pid_loaded = False
        for pid in self.pids:
            addr = self._find_py_runtime_addr(pid)
            if addr is None:
                print("[py_stack] skipping pid {} (no _PyRuntime)".format(pid),
                      file=sys.stderr)
                continue
            try:
                runtime_map[ctypes.c_uint32(pid)] = ctypes.c_uint64(addr)
                any_pid_loaded = True
            except Exception as ex:
                print("[py_stack] failed to add pid {} to map: {}".format(
                    pid, ex), file=sys.stderr)

        if not any_pid_loaded:
            print("[py_stack] no PIDs had _PyRuntime resolvable; tracker disabled",
                  file=sys.stderr)
            self.bpf = None
            return

        # Populate tid map before attaching the perf event
        self._refresh_tid_map()

        # Attach perf_event sampler (hardware CPU cycles at frequency Hz)
        self.bpf.attach_perf_event(
            ev_type=PerfType.HARDWARE,
            ev_config=0,  # PERF_COUNT_HW_CPU_CYCLES
            fn_name="on_perf_event",
            sample_period=0,
            sample_freq=self.frequency,
        )

        # Open perf buffer
        self.bpf[self.perf_buffer_name()].open_perf_buffer(
            self.safe_handle_event, page_cnt=128)

        # Start periodic tid refresher (new threads spawn during workload)
        self._refresher_thread = threading.Thread(
            target=self._refresher_loop, daemon=True)
        self._refresher_thread.start()

        print("[py_stack] tracker initialized (freq={}Hz, pids={})".format(
            self.frequency, ", ".join(str(p) for p in self.pids)),
            file=sys.stderr)

    def handle_event(self, cpu, data, size):
        event = self.bpf["py_samples"].event(data)
        pid = event.pid
        frames = []
        for i in range(event.stack_depth):
            code_addr = event.code_addrs[i]
            if code_addr == 0:
                continue
            func_name, filename, lineno = self._resolve_code(pid, code_addr)
            short_file = os.path.basename(filename) if filename else "?"
            frames.append("{} ({}:{})".format(func_name, filename or "?", lineno))
        if not frames:
            return

        # frames[0] is innermost (leaf, currently running)
        # Build folded stack root-first for flamegraph convention
        leaf_func, leaf_file, leaf_lineno = self._resolve_code(
            pid, event.code_addrs[0])
        stack_str = ";".join(reversed(frames))

        # Lookup container ids using the resolver (consistent with other trackers)
        container_pid, _ = self.resolver.get_container_ids(pid, event.host_tid)
        thread_name = self.resolver.get(pid, event.host_tid)

        doc = {
            "metric": self.METRIC_NAME,
            "server_name": self.env_name,
            "machine_ip": self.machine_ip,
            "pid": pid,
            "tid": event.host_tid,
            "container_pid": container_pid,
            "container_tid": event.container_tid,
            "comm": self.comm_cache.get(pid, event.host_tid),
            "thread_name": thread_name,
            "stack": stack_str,
            "stack_depth": int(event.stack_depth),
            "leaf_func": leaf_func,
            "leaf_file": leaf_file or "",
            "leaf_lineno": int(leaf_lineno) if leaf_lineno else 0,
            "start_time": ktime_to_iso(event.ts),
            "published_date": now_iso(),
        }
        self.emit(doc)

    def stop(self):
        self._refresher_stop = True


# =============================================================================
# Main
# =============================================================================

def main():
    parser = argparse.ArgumentParser(
        description="eBPF monitor with ClickHouse + Elasticsearch ingestion")
    parser.add_argument("-p", "--pid", nargs='+', required=True,
                        help="Gunicorn worker host PIDs")
    parser.add_argument("-e", "--env", required=True,
                        help="Environment name (server_name in events)")
    parser.add_argument("--pyspy-bin", default="py-spy")
    parser.add_argument("--pyspy-interval", type=int, default=30)
    parser.add_argument("--gil-min-wait-ms", type=float, default=1.0)
    # Include waiter/holder py_stack in gil_wait doc only when duration_ms >= this
    # (0 = always). Walk still happens in BPF regardless.
    parser.add_argument("--gil-py-min-ms", type=float, default=0.0,
                        help="Minimum duration_ms to include Python stack in gil_wait doc")
    # Safety flag: when disabled, gil_target_pid_to_runtime stays empty and
    # BPF's null-check skips the whole py stack walk. Use for production
    # rollout: deploy code with walk always available, toggle on selectively.
    # BooleanOptionalAction was added in Python 3.9; use a fallback for older
    # host Python versions still in the fleet.
    if hasattr(argparse, "BooleanOptionalAction"):
        parser.add_argument("--gil-py-enable",
                            action=argparse.BooleanOptionalAction, default=True,
                            help="Enable Python stack walk in gil_wait BPF handler "
                                 "(default: True). Use --no-gil-py-enable to disable.")
    else:
        parser.add_argument("--gil-py-enable", dest="gil_py_enable",
                            action="store_true", default=True,
                            help="Enable Python stack walk in gil_wait BPF handler "
                                 "(default: True).")
        parser.add_argument("--no-gil-py-enable", dest="gil_py_enable",
                            action="store_false",
                            help="Disable Python stack walk in gil_wait BPF handler.")
    parser.add_argument("--offcpu-min-total-ms", type=float, default=20.0)
    parser.add_argument("--offcpu-max-stack-depth", type=int, default=20)
    # Include py_stack in off_cpu doc only when total_ms >= this (0 = always).
    parser.add_argument("--offcpu-py-min-ms", type=float, default=0.0,
                        help="Minimum total_ms to include Python stack in off_cpu doc")
    # Safety flag: when disabled, off_cpu_target_pid_to_runtime stays empty
    # and BPF's null-check skips the whole py stack walk on every event.
    if hasattr(argparse, "BooleanOptionalAction"):
        parser.add_argument("--offcpu-py-enable",
                            action=argparse.BooleanOptionalAction, default=True,
                            help="Enable Python stack walk in off_cpu BPF handler "
                                 "(default: True). Use --no-offcpu-py-enable to disable.")
    else:
        parser.add_argument("--offcpu-py-enable", dest="offcpu_py_enable",
                            action="store_true", default=True,
                            help="Enable Python stack walk in off_cpu BPF handler "
                                 "(default: True).")
        parser.add_argument("--no-offcpu-py-enable", dest="offcpu_py_enable",
                            action="store_false",
                            help="Disable Python stack walk in off_cpu BPF handler.")
    parser.add_argument("--handoff-min-ms", type=float, default=0.0)
    parser.add_argument("--rq-queue-size-interval", type=float, default=1.0)
    parser.add_argument("--rq-request-count-interval", type=float, default=15.0)
    # py_stack profiler options
    parser.add_argument("--pystack-frequency", type=int, default=99,
                        help="PyStackProfiler perf_event sampling frequency in Hz")
    parser.add_argument("--pystack-tid-refresh-interval", type=float, default=10.0,
                        help="PyStackProfiler host->container TID map refresh interval (s)")
    parser.add_argument("--enable", nargs='+',
                        choices=["gc", "gil", "offcpu", "handoff",
                                 "tcp_handshake", "tcp_accept", "tcp_connect",
                                 "tcp_loss", "host_net_health", "py_stack"],
                        default=["gc", "gil", "offcpu", "handoff", "tcp_handshake",
                                 "tcp_accept", "tcp_connect", "tcp_loss",
                                 "host_net_health"])
    parser.add_argument("--disable-request-queue", action="store_true")
    parser.add_argument("--disable-mutex", action="store_true")

    # --- network tracker options ---
    parser.add_argument("--loss-filter-ip", default=None,
                        help="TcpLossTracker: only emit events involving this IP")
    parser.add_argument("--hnh-interface", default="eth0",
                        help="HostNetHealthTracker: NIC (default: auto-detect)")
    parser.add_argument("--hnh-interval", type=int, default=30,
                        help="HostNetHealthTracker: snapshot interval seconds")
    parser.add_argument("--hnh-procs", default="nginx,gunicorn",
                        help="HostNetHealthTracker: comma-separated process "
                             "names for fd tracking")

    parser.add_argument("--clickhouse-url", default="")
    parser.add_argument("--clickhouse-user", default="default")
    parser.add_argument("--clickhouse-password", default="")
    parser.add_argument("--clickhouse-database", default="default")
    # Larger batch + longer flush interval => fewer, bigger inserts => fewer
    # ClickHouse parts to merge. Bounded by --ch-queue-max (drops on overflow),
    # so memory on the host stays capped. See BATCHING_FIX.md.
    parser.add_argument("--ch-batch-size", type=int, default=5000)
    parser.add_argument("--ch-flush-interval", type=float, default=30.0)
    parser.add_argument("--ch-queue-max", type=int, default=100000)

    parser.add_argument("--es-url", default="")
    parser.add_argument("--es-user", default="elastic")
    parser.add_argument("--es-password", default="")
    parser.add_argument("--es-verify-certs", action="store_true")
    parser.add_argument("--disable-es", action="store_true")

    parser.add_argument("--also-stdout", action="store_true")

    args = parser.parse_args()

    # ---- self-restart scheduler ----
    # After MAX_UPTIME_SEC, spawn ebpf_profiling.sh which will kill us and
    # relaunch a fresh monitor. Prevents stack_traces map from filling up
    # (which silently breaks off_cpu after ~3-4 hours of runtime).
    def _restart_scheduler():
        MAX_UPTIME_SEC = 3600  # 1 hour
        time.sleep(MAX_UPTIME_SEC)
        print("[main] max uptime reached, triggering restart via ebpf_profiling.sh",
              file=sys.stderr)
        try:
            script = os.path.join(os.path.dirname(os.path.abspath(__file__)), "ebpf_profiling.sh")
            if not os.path.exists(script):
                print("[main] restart script not found at {}, staying alive".format(
                    script), file=sys.stderr)
                return
            subprocess.Popen(
                ["bash", script],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                start_new_session=True,
            )
        except Exception as ex:
            print("[main] restart trigger failed: {}".format(ex), file=sys.stderr)

    threading.Thread(target=_restart_scheduler, daemon=True).start()

    machine_ip = get_machine_ip()
    pids = [int(p) for p in args.pid]

    print("=" * 60, file=sys.stderr)
    print("Combined eBPF monitor starting", file=sys.stderr)
    print("  env:           {}".format(args.env), file=sys.stderr)
    print("  machine_ip:    {}".format(machine_ip), file=sys.stderr)
    print("  pids:          {}".format(", ".join(str(p) for p in pids)),
          file=sys.stderr)
    print("  trackers:      {}".format(", ".join(args.enable)), file=sys.stderr)
    print("  request-queue: {}".format(
        "disabled" if args.disable_request_queue else "enabled"), file=sys.stderr)
    print("  mutex:         {}".format(
        "disabled" if args.disable_mutex else "enabled"), file=sys.stderr)
    if args.clickhouse_url:
        print("  clickhouse:    {} db={} batch={} flush={}s".format(
            args.clickhouse_url, args.clickhouse_database,
            args.ch_batch_size, args.ch_flush_interval), file=sys.stderr)
    else:
        print("  clickhouse:    disabled", file=sys.stderr)
    if args.es_url and not args.disable_es:
        print("  elasticsearch: {} (verify_certs={})".format(
            args.es_url, args.es_verify_certs), file=sys.stderr)
    else:
        print("  elasticsearch: disabled", file=sys.stderr)
    print("=" * 60, file=sys.stderr)

    resolver = ThreadNameResolver(
        pids=pids, interval=args.pyspy_interval, pyspy_bin=args.pyspy_bin,
    )
    resolver.start()
    comm_cache = CommCache()

    writer = None
    if args.clickhouse_url or (args.es_url and not args.disable_es):
        writer = EventWriter(
            ch_url=args.clickhouse_url or None,
            ch_user=args.clickhouse_user,
            ch_password=args.clickhouse_password,
            ch_database=args.clickhouse_database,
            es_url=(args.es_url if (args.es_url and not args.disable_es) else None),
            es_user=args.es_user,
            es_password=args.es_password,
            es_verify_certs=args.es_verify_certs,
            batch_size=args.ch_batch_size,
            flush_interval=args.ch_flush_interval,
            queue_max=args.ch_queue_max,
            env_name=args.env,
        )
        writer.start()

    trackers = []
    handoff_tracker = None
    mutex_tracker = None
    py_stack_tracker = None

    if "gc" in args.enable:
        trackers.append(GCPauseTracker(
            pids, args.env, machine_ip, resolver, comm_cache,
            writer=writer, also_stdout=args.also_stdout))
    if "gil" in args.enable:
        trackers.append(GILWaitTracker(
            pids, args.env, machine_ip, resolver, comm_cache,
            writer=writer, also_stdout=args.also_stdout,
            min_wait_ms=args.gil_min_wait_ms,
            py_min_ms=args.gil_py_min_ms,
            py_enable=args.gil_py_enable))
    if "offcpu" in args.enable:
        trackers.append(OffCPUStackTracker(
            pids, args.env, machine_ip, resolver, comm_cache,
            writer=writer, also_stdout=args.also_stdout,
            min_total_ms=args.offcpu_min_total_ms,
            max_stack_depth=args.offcpu_max_stack_depth,
            py_min_ms=args.offcpu_py_min_ms,
            py_enable=args.offcpu_py_enable))

    if not args.disable_mutex:
        mutex_tracker = MutexLockTracker(
            pids, args.env, machine_ip, resolver, comm_cache,
            writer=writer, also_stdout=args.also_stdout)
        trackers.append(mutex_tracker)

    if "handoff" in args.enable:
        handoff_tracker = HandoffTracker(
            pids, args.env, machine_ip, resolver, comm_cache,
            writer=writer, also_stdout=args.also_stdout,
            min_handoff_ms=args.handoff_min_ms,
            mutex_tracker=mutex_tracker,
            queue_size_interval=args.rq_queue_size_interval,
            request_count_interval=args.rq_request_count_interval,
        )
        trackers.append(handoff_tracker)

    # --- network trackers ---
    host_net_health_tracker = None

    # TcpHandshakeTracker is the MERGED inbound-accept + outbound-connect
    # tracker (one tcp_set_state kprobe — required on kernel 4.14, where two
    # BPF programs cannot both kprobe the same function). Enabled if any of
    # tcp_handshake / tcp_accept / tcp_connect is requested.
    if any(name in args.enable
           for name in ("tcp_handshake", "tcp_accept", "tcp_connect")):
        trackers.append(TcpHandshakeTracker(
            pids, args.env, machine_ip, resolver, comm_cache,
            writer=writer, also_stdout=args.also_stdout))

    if "tcp_loss" in args.enable:
        trackers.append(TcpLossTracker(
            pids, args.env, machine_ip, resolver, comm_cache,
            writer=writer, also_stdout=args.also_stdout,
            filter_ip=args.loss_filter_ip))

    if "host_net_health" in args.enable:
        host_net_health_tracker = HostNetHealthTracker(
            pids, args.env, machine_ip, resolver, comm_cache,
            writer=writer, also_stdout=args.also_stdout,
            interface=args.hnh_interface,
            interval=args.hnh_interval,
            procs=args.hnh_procs)
        trackers.append(host_net_health_tracker)

    # --- python stack profiler ---
    if "py_stack" in args.enable:
        py_stack_tracker = PyStackProfilerTracker(
            pids, args.env, machine_ip, resolver, comm_cache,
            writer=writer, also_stdout=args.also_stdout,
            frequency=args.pystack_frequency,
            tid_refresh_interval=args.pystack_tid_refresh_interval,
        )
        trackers.append(py_stack_tracker)

    for tracker in trackers:
        try:
            tracker.setup()
        except Exception as ex:
            print("[main] tracker {} setup FAILED: {}".format(
                tracker.METRIC_NAME, ex), file=sys.stderr)
            traceback.print_exc(file=sys.stderr)

    if not trackers:
        print("[main] no trackers enabled, exiting", file=sys.stderr)
        sys.exit(1)

    if handoff_tracker is not None and not args.disable_request_queue:
        if handoff_tracker.bpf is not None:
            handoff_tracker.start_periodic_emitter()
        else:
            print("[main] handoff tracker BPF not loaded, skipping periodic emitter",
                  file=sys.stderr)

    if host_net_health_tracker is not None:
        host_net_health_tracker.start_periodic_emitter()

    print("[main] all trackers ready, entering event loop", file=sys.stderr)

    try:
        while True:
            for tracker in trackers:
                if tracker.bpf is None:
                    continue
                if tracker.perf_buffer_name() is None:
                    continue
                try:
                    tracker.bpf.perf_buffer_poll(timeout=100)
                except Exception as ex:
                    print("[{}] poll error: {}".format(
                        tracker.METRIC_NAME, ex), file=sys.stderr)
    except KeyboardInterrupt:
        print("\n[main] interrupted, draining...", file=sys.stderr)
    finally:
        if handoff_tracker is not None:
            handoff_tracker.stop()
        if host_net_health_tracker is not None:
            host_net_health_tracker.stop()
        if py_stack_tracker is not None:
            py_stack_tracker.stop()
        # Stop off_cpu and gil_wait tid refreshers
        for t in trackers:
            if isinstance(t, (OffCPUStackTracker, GILWaitTracker)):
                t.stop()
        if writer is not None:
            writer.stop(drain_timeout=10.0)
        print("[main] shutdown complete", file=sys.stderr)


if __name__ == "__main__":
    main()