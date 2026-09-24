# python-ebpf-profiling

eBPF-powered Python profiling toolkit — CPU profiling, GC pauses, GIL contention, off-CPU analysis, network health.

Built for **production** use. Walks CPython frame chains directly from BPF — no code changes, no restarts, minimal overhead.

## Trackers

| Tracker | What it catches | ClickHouse table |
|---|---|---|
| **GC Pause** | Python garbage collection pauses via uprobe | ebpf_gc_pause |
| **GIL Wait** | GIL contention with full Python stack walk in BPF | ebpf_gil_wait |
| **Off-CPU** | Why threads sleep — kernel + user + Python stacks | ebpf_off_cpu |
| **Handoff** | Request queue handoff latency between threads | ebpf_handoff |
| **Mutex Lock** | pthread_mutex_lock hold time | (polled by handoff) |
| **Python Stack Profiler** | Continuous CPU profiler, walks Python frames in eBPF | ebpf_py_stacks |
| **TCP Handshake** | Inbound accept + outbound connect latency | ebpf_tcp_accept / ebpf_tcp_connect |
| **TCP Loss** | Retransmits, RSTs, zero windows with congestion context | ebpf_tcp_loss |
| **Host Net Health** | Full network health snapshot — fd usage, port exhaustion | ebpf_host_net_health |

## Requirements

- Linux kernel 4.14+
- CPython 3.11 (struct offsets are version-specific)
- BCC (BPF Compiler Collection)
- Root access (eBPF requires CAP_BPF)

## Quick Start

```bash
# Stdout mode — no database needed
sudo python3 ebpf_monitor.py \
    -p <PID1> <PID2> \
    -e my-env \
    --also-stdout

# Enable specific trackers
sudo python3 ebpf_monitor.py \
    -p <PID> \
    -e my-env \
    --enable gc gil offcpu \
    --also-stdout
```

Output is JSON — pipe to `jq` for pretty printing:

```bash
sudo python3 ebpf_monitor.py -p <PID> -e my-env --also-stdout | jq .
```

## With ClickHouse + Elasticsearch (optional)

```bash
sudo python3 ebpf_monitor.py \
    -p <PID1> <PID2> \
    -e my-env \
    --clickhouse-url http://localhost:8123 \
    --es-url https://localhost:9200 \
    --es-user elastic \
    --es-password '<password>'
```

## How It Works

### GIL Wait Tracker

Attaches uprobes to CPython's `take_gil` and `drop_gil`. Walks the Python frame chain directly in BPF to capture the full Python stack at the point of GIL contention — no py-spy, no ptrace, pure BPF.

### Off-CPU Tracker

Uses `finish_task_switch` tracepoint to catch every context switch. When a tracked thread goes off-CPU, records the kernel + user + Python stack. Reports total off-CPU time per unique stack.

### GC Pause Tracker

Attaches uprobes to `gc_collect_main` entry and return. Measures exact GC pause duration per generation.

### Python Stack Profiler

Uses `perf_event` sampling at configurable frequency (default 99 Hz). On each sample, walks the CPython frame chain from the current thread state to build a full Python call stack — like py-spy but running inside the kernel.

### TCP Handshake Tracker

Single `tcp_set_state` kprobe handles both inbound (accept) and outbound (connect) tracking. Measures TCP handshake latency for every connection.

### Host Net Health Tracker

Periodic userspace snapshot combining `ss` socket stats, `ethtool` AWS ENA counters, and `/proc` fd usage into a single health document. Detects port exhaustion, fd leaks, and AWS throttling.

## Architecture

```
┌─────────────────────────────────────────┐
│           eBPF (kernel space)           │
│  ┌─────────┐ ┌─────────┐ ┌───────────┐ │
│  │ uprobes │ │ kprobes │ │ perf_event│ │
│  │ GC, GIL │ │ tcp,    │ │ CPU sample│ │
│  │         │ │ sched   │ │           │ │
│  └────┬────┘ └────┬────┘ └─────┬─────┘ │
│       │           │             │       │
│       └───────────┼─────────────┘       │
│                   │                     │
│            perf_buffer                  │
└───────────────────┼─────────────────────┘
                    │
┌───────────────────┼─────────────────────┐
│        User space │                     │
│           ┌───────▼────────┐            │
│           │ ebpf_monitor.py│            │
│           └───────┬────────┘            │
│                   │                     │
│     ┌─────────────┼──────────────┐      │
│     │             │              │      │
│  ┌──▼───┐   ┌────▼─────┐  ┌────▼────┐  │
│  │stdout│   │ClickHouse│  │   ES    │  │
│  │(JSON)│   │          │  │         │  │
│  └──────┘   └──────────┘  └─────────┘  │
└─────────────────────────────────────────┘
```

## Configuration Options

| Flag | Default | Description |
|---|---|---|
| `-p` | required | Process IDs to monitor |
| `-e` | required | Environment name |
| `--enable` | all | Trackers to enable: gc, gil, offcpu, handoff, tcp_handshake, tcp_loss, host_net_health, py_stack |
| `--also-stdout` | false | Print events to stdout as JSON |
| `--clickhouse-url` | "" | ClickHouse HTTP endpoint |
| `--es-url` | "" | Elasticsearch endpoint |
| `--gil-min-wait-ms` | 1.0 | Minimum GIL wait to report |
| `--offcpu-min-total-ms` | 20.0 | Minimum off-CPU time to report |
| `--pystack-frequency` | 99 | CPU profiler sampling frequency (Hz) |

## Files

| File | Description |
|---|---|
| `ebpf_monitor.py` | Main monitor — all trackers except network |
| `network_trackers.py` | TCP handshake, TCP loss, host network health trackers |

## Limitations

- Currently supports **CPython 3.11** only (struct offsets are hardcoded)
- Requires **BCC** installed on the host
- Must run as **root**
- Python stack walking adds ~1-2% CPU overhead when enabled

## Roadmap

- [ ] CPython 3.12 support
- [ ] CPython 3.13 free-threaded support
- [ ] Grafana dashboard templates
- [ ] SQLite backend for local analysis
- [ ] Docker/container-aware PID resolution improvements

## License

Apache 2.0

## Author

**Deepanshu Kartikey** — Performance Engineer, Linux kernel contributor

- LinkedIn: https://www.linkedin.com/in/deepanshu-kartikey-16024498/
- Website: https://deepanshukartikey.dev
- Kernel patches: https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/log/?qt=author&q=deepanshu
