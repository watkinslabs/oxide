// Wide formatted I/O (docs/59§6 G6) — wprintf/wscanf families built on the
// narrow printf/scanf engines. Output: the wide format template (wchar_t) is
// transcoded to a UTF-8 narrow format string, with bare %c→%lc and %s→%ls so
// the narrow engine reads the wide varargs; the produced UTF-8 bytes go to the
// stream as-is, or are decoded back to wchar_t for swprintf. Input: a focused
// wide scanf reads wide chars from a string/FILE source.
#![cfg(feature = "freestanding")]
use super::file::{set_unget, stdin_ptr, stdout_ptr, FILE};
use super::fmt::{self, Args, Sink};
use super::memstream::stream_write;
use super::wide::{getwc_raw, WEOF};
use crate::locale::wchar::{decode_utf8, encode_utf8};
use alloc::vec::Vec;
use core::ffi::{c_void, VaList};

// Transcode a wchar_t format string to a UTF-8 byte format string, rewriting a

// Module manifest: print owns wide printf; scan owns wide scanf; aliases owns isoc scanf entry points.
mod print;
mod scan;
mod aliases;
pub use aliases::*;
pub use print::*;
pub use scan::*;
