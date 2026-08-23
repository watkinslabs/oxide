//! Every layer, into one object.
//!
//! The writable layer is asked first, then each lower layer under the same
//! parent, until something says nothing below is visible. Four things can
//! interrupt that order and each one exists for a reason a container depends
//! on: an absolute redirect restarts the walk at the layer roots, a
//! metadata-only object forces the walk to keep going for data, an origin
//! record supplies a lower object no name leads to any more, and an index
//! entry supplies an upper object for a lower hardlink that was copied up
//! under a different name.

extern crate alloc;

use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;
use syscall::errno::Errno;
use vfs::InodeRef;

use crate::layers::{LayerStack, OvlEntry, OvlPath};
use crate::metacopy;
use crate::marker;
use crate::origin;
use crate::redirect;
use crate::uapi::Marker;

use super::data::Data;
use super::single::check_metacopy;
use super::walk;

/// Resolve `name` under `parent`.
///
/// `root` is the mount root's own object list, which an absolute redirect
/// restarts the walk from. `Ok(None)` means the name exists in no layer.
/// # C: O(layers · components · log n)
pub fn lookup(stack: &Arc<LayerStack>, parent: &OvlEntry, root: &OvlEntry, name: &str)
    -> Result<Option<OvlEntry>, Errno> {
    if name.len() as u32 > stack.namelen { return Err(Errno::Enametoolong); }

    // With redirects followed, or with data-only layers present, no layer can
    // be declared the last one in advance: a redirect found part-way down may
    // send the walk somewhere else entirely.
    let check_redirect = stack.config.redirect_follow() || stack.num_data() > 0;
    let last = if check_redirect { false } else { parent.lower.is_empty() };
    let mut d = Data::new(stack, name, last);

    let mut w = Walk::default();
    upper_layer(stack, parent, root, &mut d, &mut w)?;
    lower_layers(stack, parent, root, &mut d, &mut w)?;
    finish(stack, &mut d, &mut w)?;

    if w.upper.is_none() && w.lower.is_empty() { return Ok(None); }
    Ok(Some(entry(&d, w)))
}

/// What the walk has accumulated across the layers.
#[derive(Default)]
struct Walk {
    upper: Option<InodeRef>,
    lower: Vec<OvlPath>,
    /// Lower object named by the upper object's origin record rather than by
    /// a name in any layer.
    origin_path: Option<OvlPath>,
    /// The lower object this one's identity comes from, once verified.
    origin: Option<InodeRef>,
    opaque: bool,
    upper_metacopy: bool,
    metacopy_size: usize,
    indexed: bool,
    lowerdata_redirect: Option<String>,
    lowerdata: Option<OvlPath>,
}

/// Walk the writable layer. # C: O(components · log n)
fn upper_layer(stack: &Arc<LayerStack>, parent: &OvlEntry, root: &OvlEntry, d: &mut Data,
               w: &mut Walk) -> Result<(), Errno> {
    let (Some(ud), Some(ul)) = (&parent.upper, &stack.upper) else { return Ok(()) };
    w.upper = walk::layer(ud, d, ul)?;
    if let Some(u) = &w.upper {
        if !d.is_dir {
            // A copied-up non-directory keeps its lower identity in a record
            // rather than through a name, because the name it was copied from
            // may since have been replaced.
            w.origin_path = origin::get(&stack.config, u, Marker::Origin)
                .and_then(|rec| origin::decode(stack, &rec));
            if d.metacopy > 0 { w.upper_metacopy = true; }
            w.metacopy_size = d.metacopy;
        }
    }
    if let Some(r) = &d.redirect {
        d.upperredirect = Some(r.clone());
        if r.starts_with('/') { let _ = root; }
    }
    w.opaque = d.opaque;
    Ok(())
}

/// Walk each lower layer under the parent, restarting at the mount root when
/// an absolute redirect says to. # C: O(layers · components · log n)
fn lower_layers(stack: &Arc<LayerStack>, parent: &OvlEntry, root: &OvlEntry, d: &mut Data,
                w: &mut Walk) -> Result<(), Errno> {
    // An absolute redirect on the upper object already moved the search to the
    // layer roots before the first lower layer is asked.
    let mut from_root = d.upperredirect.as_deref().is_some_and(|r| r.starts_with('/'));
    let mut i = 0usize;
    while !d.stop {
        let poe = if from_root { root } else { parent };
        if i >= poe.lower.len() { break; }
        let lower = poe.lower[i].clone();
        if lower.layer.data_only {
            i += 1;
            continue;
        }
        if !d.may_follow() { return Err(Errno::Eperm); }
        if !stack.config.redirect_follow() && stack.num_data() == 0 {
            d.last = i == poe.lower.len() - 1;
        } else if d.is_dir || stack.num_data() == 0 {
            d.last = lower.layer.idx == stack.num_merged_lower();
        }

        if let Some(this) = walk::layer(&lower.inode, d, &lower.layer)? {
            let first = w.lower.is_empty();
            if let Some(u) = w.upper.clone() {
                if first && !stack.noxattr() && d.is_dir { fix_origin(stack, &this, &u, parent)?; }
                if first && verify_needed(stack, d, w) {
                    match verify_origin(stack, &u, &this) {
                        Ok(()) => w.origin = Some(this.clone()),
                        Err(e) => { if d.is_dir { break; } return Err(e); }
                    }
                }
            }
            if w.upper.is_none() && !d.is_dir && first && d.metacopy > 0 {
                w.metacopy_size = d.metacopy;
            }
            // Only the TOPMOST metadata-only object is kept: the ones below it
            // say the same thing, and keeping them would make the list claim
            // more layers hold this object than really do. The loop still
            // continues, because one of them may carry the absolute redirect
            // that finds the data.
            if !(d.metacopy > 0 && !first) {
                w.lower.push(OvlPath { layer: lower.layer.clone(), inode: this });
            }
            if d.stop { break; }
            if d.absolute_redirect && !from_root {
                from_root = true;
                i = lower.layer.idx.saturating_sub(1);
                continue;
            }
        }
        i += 1;
    }
    Ok(())
}

/// Is the lower object required to match the upper one's recorded origin?
///
/// For a directory this is the `nfs_export` consistency check; for a
/// non-directory it is what keeps the index honest, since an index entry keyed
/// on the wrong origin would hand out the wrong inode.
/// # C: O(1)
fn verify_needed(stack: &LayerStack, d: &Data, w: &Walk) -> bool {
    let verify_lower = stack.config.nfs_export && stack.config.index;
    (d.is_dir && verify_lower) || (!d.is_dir && stack.config.index && w.origin_path.is_some())
}

/// Check the upper object's origin record against the lower object found by
/// name. # C: O(log n)
fn verify_origin(stack: &LayerStack, upper: &InodeRef, lower: &InodeRef) -> Result<(), Errno> {
    let Some(rec) = origin::encode(&stack.config, lower, false) else { return Ok(()) };
    origin::verify(&stack.config, upper, Marker::Origin, &rec, false)
}

/// Give a merged directory whose upper half has no origin record one, so the
/// pair keeps a single identity from now on.
///
/// The parent is marked impure at the same time: it now holds an entry whose
/// lower origin has to be resolved rather than read off the name, and a
/// directory read that skipped that resolution would report the upper inode
/// number for an object whose `stat` reports the lower one.
/// # C: O(log n)
fn fix_origin(stack: &LayerStack, lower: &InodeRef, upper: &InodeRef, parent: &OvlEntry)
    -> Result<(), Errno> {
    if origin::present(&stack.config, upper) { return Ok(()); }
    let Some(rec) = origin::encode(&stack.config, lower, false) else { return Ok(()) };
    origin::set(&stack.config, upper, &rec)?;
    if let Some(pu) = &parent.upper {
        let _ = marker::set_yes(&stack.config, pu, Marker::Impure, Errno::Eio);
    }
    Ok(())
}

/// Resolve what the layer walk left open: data for a metadata-only object, an
/// origin with no name, and the index entry that ties a copied-up hardlink to
/// its upper object. # C: O(log n)
fn finish(stack: &Arc<LayerStack>, d: &mut Data, w: &mut Walk) -> Result<(), Errno> {
    // Data in a data-only layer is not looked up now: no name reaches those
    // layers, so it costs a whole path walk that most opens never need.
    if d.metacopy > 0 && !w.lower.is_empty() && stack.num_data() > 0 && d.absolute_redirect {
        w.lowerdata_redirect = d.redirect.clone();
        if let Some(redirect) = &w.lowerdata_redirect {
            w.lowerdata = lookup_data_layers(stack, redirect);
        }
        d.metacopy = 0;
    } else if !d.may_follow() {
        return Err(Errno::Eperm);
    }

    // A metadata-only object with nothing below it has no contents at all.
    // Presenting it as an empty file would silently lose the data, so the
    // lookup fails instead.
    if d.metacopy > 0 || (w.upper_metacopy && w.lower.is_empty()) { return Err(Errno::Eio); }

    if !d.is_dir && w.upper.is_some() && w.lower.is_empty() {
        if let Some(op) = w.origin_path.take() {
            w.origin = Some(op.inode.clone());
            w.lower.push(op);
        }
    }
    if w.upper_metacopy && stack.config.verity_mode != crate::config::VerityMode::Off {
        validate_verity(stack, w.upper.as_ref(), w.lowerdata.as_ref()
                        .or_else(|| w.lower.last()))?;
    }
    if w.upper.is_none() && !w.lower.is_empty() { w.origin = Some(w.lower[0].inode.clone()); }

    if w.origin.is_some() && stack.has_index() && (!d.is_dir || stack.index_all()) {
        index(stack, d, w)?;
    }
    Ok(())
}

/// Compare a metacopy record with the digest owned by its lower filesystem.
/// # C: O(descriptor + chain)
fn validate_verity(stack: &LayerStack, upper: Option<&InodeRef>, lower: Option<&OvlPath>)
    -> Result<(), Errno> {
    let Some(upper) = upper else { return Err(Errno::Eio) };
    let marker = marker::get(&stack.config, upper, Marker::Metacopy).ok_or(Errno::Eio)?;
    let record = metacopy::decode(&marker)?;
    if !record.has_digest() {
        return if stack.config.verity_mode == crate::config::VerityMode::Require {
            Err(Errno::Eio)
        } else { Ok(()) };
    }
    let lower = lower.ok_or(Errno::Eio)?;
    let got = lower.inode.i_op().verity_digest(&lower.inode)
        .map_err(crate::err::to_errno)?.ok_or(Errno::Eio)?;
    if got.0 != record.digest_algo || got.1 != record.digest { return Err(Errno::Eio); }
    Ok(())
}

/// Find the index entry for this object's origin, and adopt it as the upper
/// object when no name in the writable layer leads to one.
///
/// This is what makes a copied-up hardlink still a hardlink: the second name
/// to be copied up finds the first one's upper object through the index
/// instead of making a second copy.
/// # C: O(log n)
fn index(stack: &Arc<LayerStack>, d: &mut Data, w: &mut Walk) -> Result<(), Errno> {
    let Some(idx) = &stack.indexdir else { return Ok(()) };
    let Some(o) = &w.origin else { return Ok(()) };
    let Some(rec) = origin::encode(&stack.config, o, false) else { return Ok(()) };
    let name = crate::fh::index_name(&rec)?;
    let Ok(found) = idx.lookup(&name) else { return Ok(()) };
    if crate::whiteout::is_device(&found) { return Err(Errno::Estale); }
    w.indexed = true;
    if w.upper.is_none() {
        if let Some(v) = marker::get(&stack.config, &found, Marker::Redirect) {
            redirect::check(&v)?;
            d.upperredirect = Some(String::from_utf8_lossy(&v).into_owned());
        }
        w.metacopy_size = check_metacopy(&stack.config, &found)?;
        w.upper_metacopy = w.metacopy_size > 0;
        d.metacopy = w.metacopy_size;
        if !d.may_follow() { return Err(Errno::Eperm); }
        w.upper = Some(found);
    }
    Ok(())
}

/// Assemble the object. # C: O(layers)
fn entry(d: &Data, w: Walk) -> OvlEntry {
    let upper_alias = w.upper.is_some() && !w.indexed;
    OvlEntry {
        upper_alias,
        redirect: d.upperredirect.as_deref().and_then(|r| redirect::check(r.as_bytes()).ok()),
        metacopy: w.upper_metacopy,
        opaque: w.opaque,
        xwhiteouts: d.xwhiteouts,
        indexed: w.indexed,
        lowerdata_redirect: w.lowerdata_redirect,
        lowerdata: w.lowerdata,
        upper: w.upper,
        lower: w.lower,
        impure: false,
        whiteouts: false,
    }
}

/// Resolve a metadata-only object's absolute redirect in the data-only
/// layers. The resulting path is kept on the entry, just as Linux keeps a
/// separate lowerdata path; it must not be added to the ordinary lower list.
fn lookup_data_layers(stack: &Arc<LayerStack>, redirect: &str) -> Option<OvlPath> {
    if !redirect.starts_with('/') { return None; }
    for layer in stack.data_layers() {
        let mut data = Data::new(stack, redirect, false);
        let Ok(Some(inode)) = walk::layer(&layer.root, &mut data, layer) else { continue };
        if inode.file_type() == vfs::types::FileType::Regular {
            return Some(OvlPath { layer: layer.clone(), inode });
        }
    }
    None
}
