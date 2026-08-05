# B1844 — TCP per-socket timers

| Status | Class | Sev | Issue | Evidence | Owner |
|---|---|---|---|---|---|
| FIXED ff36e7326 | DEFECT | high | TCP retransmission, delayed acknowledgements, pacing, keepalive and connection reclamation were polled for every connection by one 100 ms `ktimers` callback. One slow or spinning pass could monopolize the voluntary-preempt kernel and stop the machine. | `boot.txt` at main `0c7d85d07`: `[154.180] [WATCHDOG] soft lockup: no reschedule for 10s on tid=4096 (ktimers) ... timer_fn=0xffffffff802991c0`; that address resolves to `net::tcp_retx_timer`. Fixed by per-connection write, delayed-ACK, keepalive and cleanup timers plus bounded timer-dispatch batches; unit, architecture, size, stack, IRQ and dual-architecture boot-smoke gates pass. | B1844-tcp-per-socket-timers |
| OPEN | COVERAGE | low | The serial TTY line-echo test expects bare LF even though the default output policy correctly expands LF to CRLF, leaving `make test` red on unchanged main. | `cargo test -p serialtty tests::rx_line_reads_and_echoes_to_uart -- --exact` fails identically on main `0c7d85d07` and B1844: actual `cmd\r\n`, expected `cmd\n`. | UNCLAIMED |
