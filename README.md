# python-ebpf-profiling

eBPF-powered Python profiling toolkit for production. CPU profiling, GC pauses, GIL contention, off-CPU analysis, network health.

Walks CPython frame chains directly from BPF. No code changes, no restarts, minimal overhead.

## Trackers

| Tracker | What it catches |
|---|---|
| **GC Pause** | Python garbage collection pauses via uprobe |
| **GIL Wait** | GIL contention with full Python stack walk for both holder and waiter |
| **Off-CPU** | Why threads sleep with kernel + user + Python stacks |
| **Handoff** | Request queue handoff latency between threads (servers only: gunicorn, uwsgi) |
| **Python Stack Profiler** | Continuous CPU profiler, walks Python frames in eBPF |
| **TCP Handshake** | Inbound accept + outbound connect latency |
| **TCP Loss** | Retransmits, RSTs, zero windows with congestion context |
| **Host Net Health** | Full network health snapshot: fd usage, port exhaustion |

### About Handoff

The handoff tracker measures how long a request sits in gunicorn's queue before a worker thread picks it up. Higher handoff time means your worker threads are overloaded and not servicing requests on time. This tracker is designed for servers (gunicorn, uwsgi) and does not apply to normal Python scripts.

## Requirements

- Linux kernel 4.14+
- CPython 3.11 (struct offsets are version-specific)
- BCC (BPF Compiler Collection)
- No additional Python packages required. Only BCC (system package) and optionally py-spy for thread name resolution.

## Installation

1. Install BCC:
   ```bash
   # Ubuntu/Debian
   sudo apt install python3-bcc

   # Or follow: https://github.com/iovisor/bcc/blob/master/INSTALL.md
   ```
2. (Optional) Install py-spy for thread name resolution. Without py-spy, you will see thread IDs instead of human-readable names like "ThreadPoolExecutor-4_2":
   ```bash
   pip install py-spy
   ```
3. Clone this repo:
   ```bash
   git clone https://github.com/deepanshu406/python-ebpf-profiling.git
   cd python-ebpf-profiling
   ```
4. Run it:
   ```bash
   sudo python3 ebpf_monitor.py -p <PID> -e my-env --also-stdout
   ```

## Quick Start (stdout, no database)

```bash
sudo python3 ebpf_monitor.py \
    -p <PID1> <PID2> \
    -e my-env \
    --also-stdout
```

## Full Usage with All Trackers

```bash
sudo python3 ebpf_monitor.py \
    -p <PID1> <PID2> <PID3> \
    -e my-env \
    --enable gc gil offcpu handoff tcp_accept tcp_connect tcp_loss host_net_health py_stack \
    --hnh-interval 30 \
    --gil-min-wait-ms 10 \
    --offcpu-py-min-ms 100 \
    --gil-py-min-ms 10 \
    --also-stdout
```

What each flag does:

| Flag | Use case |
|---|---|
| `--enable gc` | Catch GC pauses slowing your app |
| `--enable gil` | Find which thread is hogging the GIL |
| `--enable offcpu` | Find why threads are sleeping instead of working |
| `--enable handoff` | Measure how long requests wait in queue before a worker picks them up |
| `--enable tcp_accept` | Measure inbound TCP handshake latency |
| `--enable tcp_connect` | Measure outbound TCP handshake latency |
| `--enable tcp_loss` | Catch retransmits, RSTs, and packet loss |
| `--enable host_net_health` | Full network health snapshot: socket states, fd usage, port exhaustion |
| `--enable py_stack` | Continuous CPU profiler sampling Python stacks |
| `--hnh-interval 30` | Take a network health snapshot every 30 seconds |
| `--gil-min-wait-ms 10` | Only report GIL waits longer than 10ms (reduces noise) |
| `--offcpu-py-min-ms 100` | Only report off-CPU events longer than 100ms |
| `--gil-py-min-ms 10` | Only walk Python stack for GIL waits longer than 10ms (reduces overhead) |
| `--also-stdout` | Print events to stdout as JSON |

## Parameters

| Flag | Default | Description |
|---|---|---|
| `-p` | required | One or more host PIDs of your Python processes |
| `-e` | required | Environment name. Tags every event for filtering |
| `--enable` | all | Space-separated list of trackers to enable |
| `--also-stdout` | false | Print every event to stdout as JSON |
| `--pyspy-bin` | `py-spy` | Optional. Path to py-spy binary for thread name resolution |
| `--gil-min-wait-ms` | 1.0 | Minimum GIL wait duration (ms) to report |
| `--gil-py-enable` | true | Enable Python stack walk in GIL tracker |
| `--gil-py-min-ms` | 0.0 | Minimum GIL wait (ms) to include Python stack |
| `--offcpu-min-total-ms` | 20.0 | Minimum off-CPU time (ms) to report |
| `--offcpu-max-stack-depth` | 20 | Maximum kernel stack depth to capture |
| `--offcpu-py-enable` | true | Enable Python stack walk in off-CPU tracker |
| `--offcpu-py-min-ms` | 0.0 | Minimum off-CPU time (ms) to include Python stack |
| `--handoff-min-ms` | 0.0 | Minimum handoff latency (ms) to report |
| `--pystack-frequency` | 99 | CPU profiler sampling frequency in Hz |
| `--pystack-tid-refresh-interval` | 10.0 | How often (seconds) to refresh TID mappings |
| `--loss-filter-ip` | none | Only emit TCP loss events for this IP |
| `--hnh-interface` | "eth0" | Network interface for host net health |
| `--hnh-interval` | 30 | Host net health snapshot interval (seconds) |
| `--hnh-procs` | "nginx,gunicorn" | Process names for fd usage tracking |
| `--disable-mutex` | false | Disable mutex lock tracker |

## Example Output

### GC Pause

Catches Python garbage collection pauses via uprobe on `gc_collect_main`.

```bash
sudo python3 ebpf_monitor.py -p <PID> -e my-env --enable gc --also-stdout
```

```json
{
  "metric": "gc_pause",
  "pid": 278760,
  "tid": 281101,
  "container_pid": 70,
  "container_tid": 1172,
  "start_time": "2026-09-24 01:00:00.457677",
  "end_time": "2026-09-24 01:00:00.458681",
  "duration_ms": 1.004,
  "thread_name": "ThreadPoolExecutor-4_3",
  "generation": 1
}
```

Field reference:

| Field | Meaning |
|---|---|
| `pid` | Host process ID |
| `tid` | Host thread ID |
| `container_pid` | Process ID inside the container (equals pid if not containerized) |
| `container_tid` | Thread ID inside the container |
| `duration_ms` | GC pause duration in milliseconds |
| `thread_name` | Thread that triggered GC (requires py-spy) |
| `generation` | Python GC generation (0, 1, or 2) |

### GIL Wait

Tracks GIL contention with full Python stack walk for both **holder** and **waiter** directly from BPF.

```bash
sudo python3 ebpf_monitor.py -p <PID> -e my-env --enable gil --gil-min-wait-ms 1 --gil-py-enable --also-stdout
```

```json
{
  "metric": "gil_wait",
  "pid": 278641,
  "tid": 278641,
  "container_pid": 27,
  "container_tid": 27,
  "duration_ms": 5.198,
  "comm": "gunicorn",
  "thread_name": "MainThread",
  "holder_tid": 278649,
  "holder_thread_name": "OtelBatchSpanRecordProcessor",
  "holder_container_tid": 35,
  "waiter_py_stack": "<module> (/usr/local/bin/gunicorn:1);run (/usr/local/lib/python3.11/site-packages/gunicorn/app/wsgiapp.py:60);run (/usr/local/lib/python3.11/site-packages/gunicorn/app/base.py:201);run (/usr/local/lib/python3.11/site-packages/gunicorn/app/base.py:69);run (/usr/local/lib/python3.11/site-packages/gunicorn/arbiter.py:195);manage_workers (/usr/local/lib/python3.11/site-packages/gunicorn/arbiter.py:564);spawn_workers (/usr/local/lib/python3.11/site-packages/gunicorn/arbiter.py:632);spawn_worker (/usr/local/lib/python3.11/site-packages/gunicorn/arbiter.py:586);init_process (/usr/local/lib/python3.11/site-packages/gunicorn/workers/gthread.py:90);init_process (/usr/local/lib/python3.11/site-packages/gunicorn/workers/base.py:86);run (/usr/local/lib/python3.11/site-packages/gunicorn/workers/gthread.py:193);select (/usr/local/lib/python3.11/selectors.py:451)",
  "waiter_py_stack_depth": 12,
  "holder_py_stack": "_bootstrap (/usr/local/lib/python3.11/threading.py:988);_bootstrap_inner (/usr/local/lib/python3.11/threading.py:1028);run (/usr/local/lib/python3.11/threading.py:971);worker (/usr/local/lib/python3.11/site-packages/opentelemetry/sdk/_shared_internal/__init__.py:163);_export (/usr/local/lib/python3.11/site-packages/opentelemetry/sdk/_shared_internal/__init__.py:179);export (/usr/local/lib/python3.11/site-packages/opentelemetry/exporter/otlp/proto/grpc/trace_exporter/__init__.py:145);_export (/usr/local/lib/python3.11/site-packages/opentelemetry/exporter/otlp/proto/grpc/exporter.py:405);_translate_data (/usr/local/lib/python3.11/site-packages/opentelemetry/exporter/otlp/proto/grpc/trace_exporter/__init__.py:140);encode_spans (/usr/local/lib/python3.11/site-packages/opentelemetry/exporter/otlp/proto/common/_internal/trace_encoder/__init__.py:52);_encode_resource_spans (/usr/local/lib/python3.11/site-packages/opentelemetry/exporter/otlp/proto/common/_internal/trace_encoder/__init__.py:60);_encode_span (/usr/local/lib/python3.11/site-packages/opentelemetry/exporter/otlp/proto/common/_internal/trace_encoder/__init__.py:115)",
  "holder_py_stack_depth": 11
}
```

Field reference:

| Field | Meaning |
|---|---|
| `duration_ms` | How long the waiter waited for the GIL |
| `thread_name` | Thread that is waiting for the GIL |
| `holder_tid` | Thread ID that is currently holding the GIL |
| `holder_thread_name` | Name of the thread holding the GIL |
| `waiter_py_stack` | Full Python call stack of the waiting thread |
| `holder_py_stack` | Full Python call stack of the holder thread |
| `waiter_py_stack_depth` | Number of frames in the waiter stack |
| `holder_py_stack_depth` | Number of frames in the holder stack |

Reading this stack:

```
Waiter (MainThread) - gunicorn's main thread is idle, waiting in select()
  gunicorn:1
    wsgiapp.py:run
      arbiter.py:manage_workers
        gthread.py:run
          selectors.py:select             <-- blocked here, waiting for GIL

Holder (OtelBatchSpanRecordProcessor) - exporting OpenTelemetry spans
  threading.py:_bootstrap
    __init__.py:worker
      trace_exporter:export
        exporter.py:_export
          trace_encoder:_encode_span      <-- holding GIL here

Insight: OpenTelemetry span export is blocking your web server for 5.2ms
```

### Off-CPU

Tracks why threads sleep with **kernel + user + Python stacks** combined in a single event.

```bash
sudo python3 ebpf_monitor.py -p <PID> -e my-env --enable offcpu --offcpu-py-min-ms 100 --offcpu-py-enable --also-stdout
```

```json
{
  "metric": "off_cpu",
  "pid": 278641,
  "tid": 280473,
  "container_pid": 27,
  "container_tid": 1023,
  "duration_ms": 130.341,
  "comm": "gunicorn",
  "thread_name": "ThreadPoolExecutor-4_2",
  "off_cpu_ms": 130.338,
  "runq_ms": 0.003,
  "prev_state": "S",
  "cpu": 1,
  "kernel_stack": ["__schedule", "__schedule", "schedule", "schedule_hrtimeout_range_clock", "schedule_hrtimeout_range", "do_poll.constprop.0", "do_sys_poll", "__arm64_sys_ppoll", "invoke_syscall", "el0_svc_common.constprop.0", "do_el0_svc", "el0_svc", "el0t_64_sync_handler"],
  "user_stack": ["__poll [libc-2.31.so]", "internal_select.isra.0 [_socket.cpython-311-aarch64-linux-gnu.so]", "sock_call_ex [_socket.cpython-311-aarch64-linux-gnu.so]", "sock_recv_guts [_socket.cpython-311-aarch64-linux-gnu.so]", "sock_recv_into [_socket.cpython-311-aarch64-linux-gnu.so]", "method_vectorcall_VARARGS_KEYWORDS [python3.11]", "PyObject_Vectorcall [python3.11]", "_PyEval_EvalFrameDefault [python3.11]", "_PyEval_Vector [python3.11]", "PyObject_VectorcallMethod [python3.11]", "_bufferedreader_raw_read [python3.11]", "_bufferedreader_fill_buffer [python3.11]", "_buffered_readline [python3.11]", "_io__Buffered_readline [python3.11]", "_PyEval_EvalFrameDefault [python3.11]", "_PyEval_Vector [python3.11]", "method_vectorcall [python3.11]", "PyObject_Call [python3.11]", "_PyEval_EvalFrameDefault [python3.11]", "_PyEval_Vector [python3.11]"],
  "py_stack": "inner (/usr/local/lib/python3.11/site-packages/django/core/handlers/exception.py:53);__call__ (/usr/local/lib/python3.11/site-packages/material/frontend/middleware.py:45);inner (/usr/local/lib/python3.11/site-packages/django/core/handlers/exception.py:53);_get_response (/usr/local/lib/python3.11/site-packages/django/core/handlers/base.py:174);wrapped_view (/usr/local/lib/python3.11/site-packages/django/views/decorators/csrf.py:54);view (/usr/local/lib/python3.11/site-packages/django/views/generic/base.py:95);dispatch (/usr/local/lib/python3.11/site-packages/rest_framework/views.py:485);post (/home/ubuntu/foss/selector/views/delivery_modes_view.py:23);post (/usr/local/lib/python3.11/site-packages/requests/sessions.py:626);request (/usr/local/lib/python3.11/site-packages/requests/sessions.py:500);instrumented_send (/usr/local/lib/python3.11/site-packages/opentelemetry/instrumentation/requests/__init__.py:321);send (/usr/local/lib/python3.11/site-packages/requests/sessions.py:673);send (/usr/local/lib/python3.11/site-packages/requests/adapters.py:613);instrumented_urlopen (/usr/local/lib/python3.11/site-packages/opentelemetry/instrumentation/urllib3/__init__.py:449);urlopen (/usr/local/lib/python3.11/site-packages/urllib3/connectionpool.py:535);_make_request (/usr/local/lib/python3.11/site-packages/urllib3/connectionpool.py:379);getresponse (/usr/local/lib/python3.11/http/client.py:1351);begin (/usr/local/lib/python3.11/http/client.py:318);_read_status (/usr/local/lib/python3.11/http/client.py:285);readinto (/usr/local/lib/python3.11/socket.py:704)",
  "py_stack_depth": 20
}
```

Field reference:

| Field | Meaning |
|---|---|
| `off_cpu_ms` | Total time the thread was sleeping (not running) |
| `runq_ms` | Time spent in the run queue waiting for CPU after wakeup |
| `prev_state` | Thread state when it went off-CPU (S=sleeping, D=disk I/O) |
| `cpu` | CPU core the thread was on |
| `kernel_stack` | Kernel call stack showing why the thread slept |
| `user_stack` | C/CPython call stack (libc, Python interpreter frames) |
| `py_stack` | Python call stack showing your application code |
| `py_stack_depth` | Number of Python frames captured |

Reading this stack:

```
Kernel - thread went to sleep on a poll syscall
  el0t_64_sync_handler
    el0_svc
      __arm64_sys_ppoll
        do_sys_poll
          schedule                        <-- kernel put this thread to sleep

User (C/CPython) - inside socket.recv
  _PyEval_EvalFrameDefault
    _io__Buffered_readline
      sock_recv_into
        internal_select
          __poll [libc]                   <-- waiting for data on socket

Python - Django view making an outbound HTTP request
  django/core/handlers/exception.py:inner
    django/core/handlers/base.py:_get_response
      rest_framework/views.py:dispatch
        foss/selector/views/delivery_modes_view.py:post
          requests/sessions.py:post
            urllib3/connectionpool.py:urlopen
              http/client.py:getresponse
                socket.py:readinto        <-- waiting for HTTP response

Insight: Thread waited 130ms for an outbound HTTP response during a Django REST API call
```

### Handoff

Measures how long a request sits in gunicorn's queue before a worker thread picks it up. Higher handoff time means workers are overloaded. This tracker only works with servers (gunicorn, uwsgi), not normal Python scripts.

```bash
sudo python3 ebpf_monitor.py -p <PID> -e my-env --enable handoff --also-stdout
```

```json
{
  "metric": "handoff",
  "pid": 278656,
  "tid": 282566,
  "container_pid": 38,
  "container_tid": 1389,
  "duration_ms": 0.234,
  "worker_tid": 282566,
  "worker_comm": "gunicorn",
  "worker_thread_name": "ThreadPoolExecutor-4_2",
  "main_tid": 278656,
  "main_comm": "gunicorn",
  "main_thread_name": "MainThread",
  "fd": 57,
  "queue_path": "epoll_del",
  "pickup_via": "recvfrom",
  "queued_time": "2026-09-24 01:02:41.686787",
  "pickup_time": "2026-09-24 01:02:41.687021",
  "handoff_ms": 0.234
}
```

Field reference:

| Field | Meaning |
|---|---|
| `worker_thread_name` | Worker thread that picked up the request |
| `main_thread_name` | Main thread that queued the request |
| `fd` | File descriptor of the client connection |
| `queue_path` | How the request was queued (epoll_del, write, etc.) |
| `pickup_via` | How the worker picked it up (recvfrom, read, etc.) |
| `queued_time` | When the request was placed in the queue |
| `pickup_time` | When the worker started processing it |
| `handoff_ms` | Time the request waited in the queue |

### Python Stack Profiler

Continuous CPU profiler at configurable frequency. Walks CPython frame chains in eBPF.

```bash
sudo python3 ebpf_monitor.py -p <PID> -e my-env --enable py_stack --pystack-frequency 99 --also-stdout
```

```json
{
  "metric": "py_stack",
  "pid": 278641,
  "tid": 284981,
  "container_pid": 27,
  "container_tid": 1624,
  "comm": "gunicorn",
  "thread_name": "ThreadPoolExecutor-4_3",
  "stack": "inner (/usr/local/lib/python3.11/site-packages/django/core/handlers/exception.py:53);__call__ (/usr/local/lib/python3.11/site-packages/material/frontend/middleware.py:15);inner (/usr/local/lib/python3.11/site-packages/django/core/handlers/exception.py:53);__call__ (/usr/local/lib/python3.11/site-packages/material/frontend/middleware.py:45);inner (/usr/local/lib/python3.11/site-packages/django/core/handlers/exception.py:53);_get_response (/usr/local/lib/python3.11/site-packages/django/core/handlers/base.py:174);wrapped_view (/usr/local/lib/python3.11/site-packages/django/views/decorators/csrf.py:54);view (/usr/local/lib/python3.11/site-packages/django/views/generic/base.py:95);dispatch (/usr/local/lib/python3.11/site-packages/rest_framework/views.py:485);wrapper_function (/home/ubuntu/foss/service/decorators.py:1594);post (/home/ubuntu/foss/selector/views/views.py:545);process_recommendation_data2 (/home/ubuntu/foss/selector/service/recsv2.py:110);process_recommendation_data3 (/home/ubuntu/foss/selector/service/recsv2.py:123);create_final_response (/home/ubuntu/foss/selector/service/recsv2.py:2444);values (/usr/local/lib/python3.11/site-packages/django/db/models/query.py:1296);_values (/usr/local/lib/python3.11/site-packages/django/db/models/query.py:1288);set_values (/usr/local/lib/python3.11/site-packages/django/db/models/sql/query.py:2388);add_fields (/usr/local/lib/python3.11/site-packages/django/db/models/sql/query.py:2129);setup_joins (/usr/local/lib/python3.11/site-packages/django/db/models/sql/query.py:1753);names_to_path (/usr/local/lib/python3.11/site-packages/django/db/models/sql/query.py:1637)",
  "stack_depth": 20,
  "leaf_func": "names_to_path"
}
```

Field reference:

| Field | Meaning |
|---|---|
| `stack` | Full Python call stack at the moment of sampling |
| `stack_depth` | Number of Python frames captured |
| `leaf_func` | The function at the top of the stack (where CPU is being spent) |

Reading this stack:

```
Python - CPU was sampled inside Django's ORM query builder
  django/core/handlers/exception.py:inner
    django/core/handlers/base.py:_get_response
      rest_framework/views.py:dispatch
        foss/selector/views/views.py:post
          foss/selector/service/recsv2.py:process_recommendation_data2
            foss/selector/service/recsv2.py:create_final_response
              django/db/models/query.py:values
                django/db/models/sql/query.py:set_values
                  django/db/models/sql/query.py:add_fields
                    django/db/models/sql/query.py:names_to_path  <-- CPU spent here

Insight: CPU is being consumed inside Django's ORM resolving field names to database joins
```

### TCP Handshake (Connect + Accept)

Tracks both inbound accept and outbound connect latency with a single `tcp_set_state` kprobe.

```bash
sudo python3 ebpf_monitor.py -p <PID> -e my-env --enable tcp_handshake --also-stdout
```

```json
{
  "metric": "tcp_connect",
  "pid": 278656,
  "tid": 280049,
  "comm": "gunicorn",
  "family": "AF_INET",
  "src_ip": "172.17.0.2",
  "src_port": 41680,
  "dst_ip": "10.x.x.x",
  "dst_port": 6432,
  "handshake_us": 137,
  "srtt_us": 117,
  "outcome": "success"
}
```

Field reference:

| Field | Meaning |
|---|---|
| `src_ip` / `src_port` | Source address of the connection |
| `dst_ip` / `dst_port` | Destination address (e.g. database, upstream service) |
| `handshake_us` | TCP handshake duration in microseconds |
| `srtt_us` | Smoothed round-trip time in microseconds |
| `outcome` | Connection result: success or timeout |

### TCP Loss

Tracks retransmits, RSTs, zero windows with full congestion context.

```bash
sudo python3 ebpf_monitor.py -p <PID> -e my-env --enable tcp_loss --also-stdout
```

```json
{
  "metric": "tcp_loss",
  "event": "retransmit",
  "comm": "swapper/1",
  "src_ip": "172.17.0.2",
  "src_port": 44862,
  "dst_ip": "10.x.x.x",
  "dst_port": 80,
  "tcp_state": "LAST_ACK",
  "srtt_us": 198,
  "snd_cwnd": 1,
  "total_retrans": 7,
  "lost_out": 1,
  "snd_wnd": 28160,
  "rcv_wnd": 64128
}
```

Field reference:

| Field | Meaning |
|---|---|
| `event` | Type of loss event: retransmit, loss, reset, probe |
| `tcp_state` | TCP state at the time of loss |
| `srtt_us` | Smoothed round-trip time |
| `snd_cwnd` | Congestion window size (1 = fully congested) |
| `total_retrans` | Total retransmissions on this connection |
| `lost_out` | Number of lost segments |
| `snd_wnd` / `rcv_wnd` | Send and receive window sizes |

### Host Net Health

Full network health snapshot — socket states, fd usage, port exhaustion risk.

```bash
sudo python3 ebpf_monitor.py -p <PID> -e my-env --enable host_net_health --hnh-interval 30 --also-stdout
```

```json
{
  "metric": "host_net_health",
  "interface": "eth0",
  "interval_s": 30,
  "established_inbound": 14,
  "established_outbound": 11,
  "time_wait": 39,
  "close_wait": 0,
  "syn_sent": 0,
  "syn_recv": 0,
  "max_time_wait_one_dst": 18,
  "port_util_pct": 0.06,
  "delta_bw_in": 0,
  "delta_bw_out": 0,
  "delta_pps": 0,
  "delta_conntrack": 0,
  "fd_usage_json": [
    {"proc": "nginx", "pids": 5, "fd_count": 79, "fd_limit": 65535, "fd_util_pct": 0.12},
    {"proc": "gunicorn", "pids": 8, "fd_count": 573, "fd_limit": 32768, "fd_util_pct": 1.75}
  ],
  "warnings": []
}
```

Field reference:

| Field | Meaning |
|---|---|
| `established_inbound` / `outbound` | Active TCP connections in each direction |
| `time_wait` | Connections in TIME_WAIT state |
| `close_wait` | Connections in CLOSE_WAIT (possible leak if high) |
| `max_time_wait_one_dst` | Highest TIME_WAIT count to a single destination |
| `port_util_pct` | Ephemeral port utilization percentage |
| `fd_usage_json` | File descriptor usage per process |
| `warnings` | Alerts for port exhaustion, fd exhaustion, etc. |

## How It Works

### GIL Wait Tracker

Attaches uprobes to CPython's `take_gil` and `drop_gil`. Walks the Python frame chain directly in BPF to capture the full Python stack at the point of GIL contention — no py-spy, no ptrace, pure BPF.

### Off-CPU Tracker

Uses `finish_task_switch` tracepoint to catch every context switch. When a tracked thread goes off-CPU, records the kernel + user + Python stack. Reports total off-CPU time per unique stack.

### GC Pause Tracker

Attaches uprobes to `gc_collect_main` entry and return. Measures exact GC pause duration per generation.

### Python Stack Profiler

Uses `perf_event` sampling at configurable frequency (default 99 Hz). On each sample, walks the CPython frame chain from the current thread state to build a full Python call stack.

### TCP Handshake Tracker

Single `tcp_set_state` kprobe handles both inbound (accept) and outbound (connect) tracking. Measures TCP handshake latency for every connection.

### Host Net Health Tracker

Periodic userspace snapshot combining `ss` socket stats, `ethtool` counters, and `/proc` fd usage into a single health document. Detects port exhaustion, fd leaks, and network throttling.

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
│          ┌────────┼────────┐            │
│          │                 │            │
│       ┌──▼───┐       ┌────▼─────┐      │
│       │stdout│       │ClickHouse│      │
│       │(JSON)│       │(optional)│      │
│       └──────┘       └──────────┘      │
└─────────────────────────────────────────┘
```

## ClickHouse Integration (optional)

If you want to store events for long-term analysis, you can send them to ClickHouse.

```bash
sudo python3 ebpf_monitor.py \
    -p <PID1> <PID2> \
    -e my-env \
    --clickhouse-url http://localhost:8123 \
    --clickhouse-user default \
    --clickhouse-password <password> \
    --clickhouse-database default \
    --ch-batch-size 5000 \
    --ch-flush-interval 30 \
    --enable gc gil offcpu handoff tcp_accept tcp_connect tcp_loss host_net_health py_stack \
    --hnh-interval 30 \
    --gil-min-wait-ms 10 \
    --offcpu-py-min-ms 100 \
    --gil-py-min-ms 10
```

Each tracker writes to its own ClickHouse table:

| Tracker | ClickHouse table |
|---|---|
| GC Pause | `ebpf_gc_pause` |
| GIL Wait | `ebpf_gil_wait` |
| Off-CPU | `ebpf_off_cpu` |
| Handoff | `ebpf_handoff` |
| Python Stack Profiler | `ebpf_py_stacks` |
| TCP Accept | `ebpf_tcp_accept` |
| TCP Connect | `ebpf_tcp_connect` |
| TCP Loss | `ebpf_tcp_loss` |
| Host Net Health | `ebpf_host_net_health` |

ClickHouse parameters:

| Flag | Default | Description |
|---|---|---|
| `--clickhouse-url` | "" | ClickHouse HTTP endpoint |
| `--clickhouse-user` | "default" | ClickHouse username |
| `--clickhouse-password` | "" | ClickHouse password |
| `--clickhouse-database` | "default" | ClickHouse database |
| `--ch-batch-size` | 5000 | Events to batch before inserting |
| `--ch-flush-interval` | 30.0 | Max seconds before flushing a partial batch |
| `--ch-queue-max` | 100000 | Max events in queue (dropped when full) |

## Files

| File | Description |
|---|---|
| `ebpf_monitor.py` | Main monitor: all trackers except network |
| `network_trackers.py` | TCP handshake, TCP loss, host network health trackers |

## Limitations

- Currently supports **CPython 3.11** only (struct offsets are hardcoded)
- Requires **BCC** installed on the host
- Must run as **root**
- Python stack walking adds ~1-2% CPU overhead when enabled

## Roadmap

- [ ] CPython 3.12 support
- [ ] CPython 3.13 free-threaded support
- [ ] Pyroscope integration
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
