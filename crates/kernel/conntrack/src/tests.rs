// Module manifest (test tree): one child per behaviour group. Each child is
// bound by an explicit `#[path]` so it resolves against `src/tests/`, never
// against a sibling implementation file.

#[path = "tests/tuple.rs"]     mod tuple;
#[path = "tests/tcp_table.rs"] mod tcp_table;
#[path = "tests/tcp_window.rs"] mod tcp_window;
#[path = "tests/tcp_flow.rs"]  mod tcp_flow;
#[path = "tests/udp_icmp.rs"]  mod udp_icmp;
#[path = "tests/table.rs"]     mod table;
#[path = "tests/expect.rs"]    mod expect;
#[path = "tests/helper.rs"]    mod helper;
#[path = "tests/sysctl.rs"]    mod sysctl;
#[path = "tests/render.rs"]    mod render;
