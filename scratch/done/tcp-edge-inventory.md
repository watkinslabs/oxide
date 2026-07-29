# TCP edge inventory

Status: IN-PROGRESS. Branch: D353-tcp-edge-inventory. Linux owner sources:
`net/ipv4/tcp_input.c`, `tcp_output.c`, `tcp_timer.c`, and `tcp_ipv4.c`.
Oxide evidence is from `crates/kernel/net` and syscall work functions.

| Edge contract | Linux owner | Current Oxide evidence | Status | Required closure proof |
|---|---|---|---|---|
| SYN reception, listener selection, SYN backlog, syncookies, ACK promotion | `tcp_v4_rcv`, `tcp_conn_request`, `tcp_check_req` | `listen` routes to `net::sock::listen`; no TCP SYN/syncookie corpus found | Missing audit | Linux/Oxide target matrix: full/zero/negative backlog, SYN flood/cookies, duplicate SYN/ACK, close during handshake |
| Established input: sequence/window validation, delayed ACK, out-of-order queue, duplicate ACK/fast retransmit | `tcp_rcv_established`, `tcp_data_queue`, `tcp_ack` | TCP state and `tcp_info` expose retransmit counters; no target ordering corpus | Partial | packet-driven hosted fixture plus target peer: in-order, overlap, OOO, duplicate ACK, window shrink, loss/reorder |
| Output, cork/Nagle, segmentation, retransmit queue and RTO | `tcp_write_xmit`, `tcp_retransmit_skb`, `tcp_retransmit_timer` | `tcp_info.rs` reads `retx_q`; no conformance exercise of output timing | Partial | byte/errno/poll matrix for cork/NODELAY, partial write, loss/RTO/backoff, ACK release and close |
| RST, FIN, half-close, TIME_WAIT, port reuse | `tcp_reset`, `tcp_fin`, `tcp_time_wait` | hosted RST/TIME_WAIT work noted in N20; no retained target matrix | Partial | active/passive close, RST at every state, unread-data close, bind/reuseaddr/reuseport while TIME_WAIT, target differential |
| Urgent data / `MSG_OOB` / `SO_OOBINLINE` / `SIOCATMARK` | TCP input urgent path | `recvmsg/inet.rs` has urgent/OOB path; `SO_OOBINLINE` and `SIOCATMARK` routes exist | Partial | Linux/Oxide stream tests for mark ordering, peek, inline/non-inline, EINVAL/EOPNOTSUPP and poll exceptional state |
| `SO_REUSEPORT` selection and close/removal linearization | listener lookup and reuseport group | option storage/readback exists; N20 records hosted reuseport work | Partial | equal 4-tuple distribution, BPF/default selection, close/remove race, namespace/capability, target peer |
| Async errors, ICMP, `MSG_ERRQUEUE`, PMTU and `IP*_MTU_DISCOVER` | `tcp_v4_err`, error queue and route PMTU | PMTU option validation exists in `054_setsockopt`; no TCP error queue corpus | Missing | injected ICMP/PMTU, error queue ordering vs receive, EMSGSIZE/write retry, IPv4/IPv6 target differential |
| Keepalive, user timeout and orphan/retry expiry | `tcp_keepalive_timer`, write/retransmit timers | `SO_KEEPALIVE` and TCP keepalive options refresh socket state | Partial | idle probe/count/interval, peer drop, user timeout, wake/errno/poll and target time-controlled differential |
| Accept wakeups, shutdown, signal/restart and poll/epoll | listen/accept wait queues | lock-coupled connect/write waits and hosted race tests recorded; N25 remains open | Partial | blocking accept/connect/write interrupted by signal, ACK/RST/close wake races, edge-triggered poll/epoll, both targets |
| TCP diagnostics: `TCP_INFO`, queued bytes, OOB mark | `tcp_get_info`, socket ioctl | `tcp_info.rs`, queue-count and `SIOCATMARK` dispatch exist | Partial | state, RTT/cwnd/retrans, queue counters under ACK/loss/close and native/compat output differential |

## Execution order

1. Build the packet-driven hosted fixture for established input/output and
   RST/FIN before changing TCP state logic.
2. Add a Linux-oracle target probe for urgent data and `TCP_INFO`; retain x86
   frames, then ARM frames once the global boot gate is repaired.
3. Implement missing SYN/cookie, async-error/PMTU, and timeout ownership in
   the TCP stack owner only; syscall files retain ABI validation/copyout.
