//! SCO tests.
//!
//! Module manifest: one file per contract — the parameter tables and their
//! walk, the command encodings, the link's attempts, the socket surface and the
//! data path.

#[path = "param.rs"] mod param;
#[path = "cmd.rs"] mod cmd;
#[path = "conn.rs"] mod conn;
#[path = "sock.rs"] mod sock;
#[path = "data.rs"] mod data;
