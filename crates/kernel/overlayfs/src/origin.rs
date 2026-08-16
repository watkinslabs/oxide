//! Recording which lower object an upper one was copied from.
//!
//! A copied-up file keeps the inode number, and the identity, of the object it
//! came from. Without that, `cp -a` of a tree inside the overlay sees every
//! hardlinked pair become two separate files the moment one of them is
//! touched, and a program holding a file open across a write sees its
//! `st_ino` change under it.
//!
//! The record is the LOWER filesystem's own file handle, so it stays valid
//! across a remount and across a kernel that walks the layers in a different
//! order. A layer that cannot mint handles simply has no recorded origin —
//! which costs the shared identity but never wrongly claims one.

extern crate alloc;

use alloc::sync::Arc;
use alloc::vec::Vec;
use syscall::errno::Errno;
use vfs::{InodeRef, SuperBlock};

use crate::config::Config;
use crate::fh;
use crate::layers::{Layer, LayerStack, OvlPath};
use crate::marker;
use crate::uapi::Marker;

/// Mint the record naming `inode` in its own layer.
///
/// `None` when the layer cannot mint handles at all — the caller then records
/// nothing, and every feature that needs an origin is already off for this
/// mount.
/// # C: O(1)
pub fn encode(config: &Config, inode: &InodeRef, is_upper: bool) -> Option<Vec<u8>> {
    let sb = inode.i_sb()?;
    let (fid, fid_type) = vfs::export::encode_fh(&sb, inode, None)?;
    let uuid = if config.origin_uuid() { sb.s_uuid() } else { [0u8; 16] };
    fh::encode(fid_type as u8, uuid, &fid, is_upper).ok()
}

/// Does a record's recorded layer identity match `sb`?
///
/// With `uuid=off` the record carries no identity, so the only thing that can
/// be checked is that it carries NONE — a record that does carry one was
/// written by a mount with different rules and is not ours to decode.
/// # C: O(1)
pub fn uuid_match(config: &Config, sb: &SuperBlock, uuid: &[u8; 16]) -> bool {
    if config.origin_uuid() { *uuid == sb.s_uuid() } else { uuid.iter().all(|&b| b == 0) }
}

/// Resolve a record against one layer. # C: O(log N_ino)
pub fn decode_in(config: &Config, layer: &Arc<Layer>, record: &[u8]) -> Option<OvlPath> {
    let d = fh::decode(record).ok()?;
    let sb = layer.root.i_sb()?;
    if !uuid_match(config, &sb, &d.uuid) { return None; }
    let inode = vfs::export::decode_fh(&sb, &d.fid, d.fid_type as i32)?;
    Some(OvlPath { layer: layer.clone(), inode })
}

/// Resolve a record against every merged lower layer, topmost first.
///
/// The record does not say WHICH layer it belongs to when the layers share a
/// filesystem identity, so each is tried in turn and the first that resolves
/// wins — the same order a name lookup would have taken, so the two agree.
/// # C: O(layers · log N_ino)
pub fn decode(stack: &LayerStack, record: &[u8]) -> Option<OvlPath> {
    stack.merged_lower().find_map(|l| decode_in(&stack.config, l, record))
}

/// Read the record stored on an upper object. # C: O(log n)
pub fn get(config: &Config, upper: &InodeRef, m: Marker) -> Option<Vec<u8>> {
    let v = marker::get(config, upper, m)?;
    // A zero-length value means "copied up, origin unknown" — a real answer,
    // and the reason a pure upper object can be told from a copied-up one at
    // all. It is not a record, so it decodes to nothing.
    if v.is_empty() || fh::check(&v).is_err() { return None; }
    Some(v)
}

/// Is an object a copy-up rather than one created in the upper layer? True
/// even when the record is empty, because the marker's presence is the
/// answer. # C: O(log n)
pub fn present(config: &Config, upper: &InodeRef) -> bool {
    marker::present(config, upper, Marker::Origin)
}

/// Store a record, tolerating a layer that cannot hold one.
///
/// A refusal is NOT fatal: the object is already copied up and perfectly
/// usable, it merely loses the identity it shared with its lower half. Failing
/// here instead would turn an unsupported attribute into an unusable overlay.
/// # C: O(log n)
pub fn set(config: &Config, upper: &InodeRef, record: &[u8]) -> Result<(), Errno> {
    match marker::set(config, upper, Marker::Origin, record, Errno::Eopnotsupp) {
        Ok(()) => Ok(()),
        // Setting an attribute in the unprivileged namespace on a symlink or a
        // device node is refused by the layer itself, not by policy.
        Err(Errno::Eperm) | Err(Errno::Eopnotsupp) => Ok(()),
        Err(e) => Err(e),
    }
}

/// Check a stored record against `want`, optionally writing it when none is
/// stored.
///
/// `Enodata` means nothing was stored and nothing was asked to be; `Estale`
/// means something else was, which is how a directory that two different upper
/// objects claim is detected instead of silently merged with both.
/// # C: O(log n)
pub fn verify(config: &Config, inode: &InodeRef, m: Marker, want: &[u8], write: bool)
    -> Result<(), Errno> {
    match marker::get(config, inode, m) {
        None => {
            if write { marker::set(config, inode, m, want, Errno::Eopnotsupp) } else { Err(Errno::Enodata) }
        }
        Some(have) if fh::same(&have, want) => Ok(()),
        Some(_) => Err(Errno::Estale),
    }
}
