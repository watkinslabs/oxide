//! Module manifest: model records; registry database; store persistence; wire framing; client/advapi adapters.

use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File, OpenOptions};
use std::io::{self, ErrorKind, Read, Write};
use std::os::unix::io::AsRawFd;
use std::path::{Path, PathBuf};
use syscall::registry_wire;

mod model;
mod registry;
mod store;
mod wire;
mod service;
mod limits;
mod client;
mod advapi;
pub use model::*;
pub use client::Client;
pub use advapi::Advapi;
pub use wire::serve_connection;
pub use service::{serve_listener, ServerLimits};
pub use limits::REG_NOTIFY_CHANGE_LAST_SET;
use registry::*;
use limits::*;
#[cfg(test)]
mod tests;
