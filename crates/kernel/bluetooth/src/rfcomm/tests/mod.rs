//! RFCOMM tests.
//!
//! Module manifest: one file per contract — the check sequence, framing, the
//! multiplexer commands, credit flow, port negotiation, the session state
//! machine, the socket surface and the terminal binding.

#[path = "fcs.rs"] mod fcs;
#[path = "frame.rs"] mod frame;
#[path = "mcc.rs"] mod mcc;
#[path = "credit.rs"] mod credit;
#[path = "rpn.rs"] mod rpn;
#[path = "session.rs"] mod session;
#[path = "sock.rs"] mod sock;
#[path = "tty.rs"] mod tty;
