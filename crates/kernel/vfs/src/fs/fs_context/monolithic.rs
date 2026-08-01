// `mount(2)`'s monolithic `key[=val][,key[=val]]*` data string.
//
// `fsconfig(2)` hands the kernel one parameter at a time; `mount(2)` hands it
// one comma-separated blob. Both must reach the SAME verdict, or the option a
// probe reports as unsupported is still silently swallowed by the real mount —
// which is the shape every option-support query in userspace is written
// against. So the blob is split here and each piece goes through
// [`vfs_parse_fs_param`], the one admission owner; nothing re-implements the
// per-key decision.
//
// A filesystem that publishes no parameter table is the unconverted backend:
// its blob is kept VERBATIM and handed to the constructor untouched, because
// splitting a string nobody can admit would only lose information (quoted
// values, key order, repeated keys). That is the pre-table behaviour, retained
// exactly, and it is selected by [`FsContextOps::parse_monolithic`], not by a
// second parser.
//
// Ungated: pure decision logic over `&str`, so hosted tests cover it.

extern crate alloc;

use super::context::FsContext;
use super::flow::vfs_parse_fs_param;
use super::types::{FsParameter, KResult};

/// `generic_parse_monolithic`: split `data` on commas and admit each piece.
///
/// Separator semantics that matter and are easy to get wrong:
/// - an EMPTY piece (`"a,,b"`, a trailing comma, an empty blob) is skipped, not
///   an error — a filesystem that takes no options must still accept `""`;
/// - a piece with no `=` is a bare word (`fs_value_is_flag`);
/// - a piece whose `=` is at offset 0 (`"=v"`) is skipped entirely, because an
///   empty key is not a key;
/// - a piece ending in `=` carries an EMPTY string value, which is distinct
///   from a bare word (`usrjquota=` clears the journalled quota file);
/// - only the FIRST `=` splits, so a value may contain `=`.
///
/// # C: O(len data)
pub fn generic_parse_monolithic(fc: &mut FsContext, data: &str) -> KResult<()> {
    for piece in data.split(',') {
        if piece.is_empty() { continue; }
        let param = match piece.find('=') {
            None => FsParameter::flag(piece),
            Some(0) => continue,
            Some(i) => FsParameter::string(&piece[..i], &piece[i + 1..]),
        };
        vfs_parse_fs_param(fc, &param)?;
    }
    Ok(())
}

/// `parse_monolithic_mount_data`: hand the `mount(2)` data blob to the
/// context's backend, which decides between the generic split above and
/// keeping the blob whole. # C: O(len data)
pub fn parse_monolithic_mount_data(fc: &mut FsContext, data: &str) -> KResult<()> {
    let ops = fc.ops.clone();
    ops.parse_monolithic(fc, data)
}
