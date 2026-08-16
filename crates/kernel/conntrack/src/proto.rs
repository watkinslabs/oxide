// Module manifest:
// - `tcp_state`: state constants, flag classes, and the transition table.
// - `tcp_window`: sequence/window arithmetic and per-direction state.
// - `tcp`: the packet driver that joins the two and picks the timeout.
// - `udp`: unreplied/replied/stream timeout selection.
// - `icmp`: ICMP + ICMPv6 request/reply tracking and the generic fallback.

#[path = "proto/tcp_state.rs"]  pub mod tcp_state;
#[path = "proto/tcp_window.rs"] pub mod tcp_window;
#[path = "proto/tcp.rs"]        pub mod tcp;
#[path = "proto/udp.rs"]        pub mod udp;
#[path = "proto/icmp.rs"]       pub mod icmp;
