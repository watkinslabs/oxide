//! The combinations that are refused, and those quietly adjusted.
//!
//! Several features depend on each other, and the resolution depends on which
//! side the mount asked for EXPLICITLY: two named options that contradict are
//! an error the caller can fix, while a named option against a defaulted one
//! silently wins. Getting that backwards either fails mounts that every
//! container runtime issues, or silently disables the feature they asked for.
//!
//! The whole pass is a function of the option set and one privilege answer, so
//! every one of its decisions is checkable without a layer, a mount or a
//! superblock.

use syscall::errno::Errno;

use crate::config::{Config, FsyncMode, OptSet, RedirectMode, UuidMode, VerityMode, DEF_FSYNC};

/// Resolve `config` in place, given whether the caller may write the private
/// markers into the `trusted.` namespace.
///
/// Returns `EINVAL` where two explicitly named options cannot both hold, and
/// `EPERM` where a named feature needs privilege the caller does not have.
/// # C: O(1)
pub fn verify(config: &mut Config, named: OptSet, trusted_xattr: bool) -> Result<(), Errno> {
    let mut set = named;
    if config.upperdir.is_none() { no_upper(config, &mut set); }
    metacopy_needs_redirect(config, set)?;
    nfs_export_needs_index(config, &mut set)?;
    nfs_export_excludes_metacopy(config, set)?;
    if config.userxattr { userxattr_excludes(config, set)?; }
    if !config.userxattr && !trusted_xattr { needs_trusted(config, set)?; }
    Ok(())
}

/// A mount with no writable layer never writes anything, so every option that
/// only affects writing is meaningless and is dropped rather than obeyed.
/// # C: O(1)
fn no_upper(config: &mut Config, set: &mut OptSet) {
    config.workdir = None;
    if config.index && set.index { set.index = false; }
    config.index = false;
    if config.is_volatile() { config.fsync_mode = DEF_FSYNC; }
    if config.uuid == UuidMode::On { config.uuid = UuidMode::Null; }
    // Writing a redirect is an upper-layer act, so with no upper layer the
    // only distinction left is whether one is followed. Collapsing `follow`
    // to `on` here is what lets the rules below test a single value.
    if config.redirect_mode == RedirectMode::Follow { config.redirect_mode = RedirectMode::On; }
}

/// Metadata-only copy-up leaves the data behind under its original name, so
/// the upper object must be able to point at it. # C: O(1)
fn metacopy_needs_redirect(config: &mut Config, set: OptSet) -> Result<(), Errno> {
    if !config.metacopy || config.redirect_mode == RedirectMode::On { return Ok(()); }
    if set.metacopy && set.redirect { return Err(Errno::Einval); }
    if set.redirect { config.metacopy = false; } else { config.redirect_mode = RedirectMode::On; }
    Ok(())
}

/// Exporting the overlay needs a stable identity for every object, which is
/// what the index records. # C: O(1)
fn nfs_export_needs_index(config: &mut Config, set: &mut OptSet) -> Result<(), Errno> {
    if !config.nfs_export || config.index { return Ok(()); }
    if config.upperdir.is_none() && config.redirect_mode != RedirectMode::NoFollow {
        // With no upper layer there is no index to build, so the identity has
        // to come from the lower layer alone — which a followed redirect
        // breaks, since two names would decode to one object.
        config.nfs_export = false;
    } else if set.nfs_export && set.index {
        return Err(Errno::Einval);
    } else if set.index {
        config.nfs_export = false;
    } else {
        config.index = true;
    }
    Ok(())
}

/// A metacopy object has no data of its own, so a handle to it cannot be
/// resolved by a client that only sees the overlay. # C: O(1)
fn nfs_export_excludes_metacopy(config: &mut Config, set: OptSet) -> Result<(), Errno> {
    if !config.nfs_export || !config.metacopy { return Ok(()); }
    if set.nfs_export && set.metacopy { return Err(Errno::Einval); }
    if set.metacopy || config.verity_mode != VerityMode::Off {
        config.nfs_export = false;
    } else {
        config.metacopy = false;
    }
    Ok(())
}

/// With the markers in the unprivileged namespace, anyone who can write the
/// upper layer can write a marker — so the two features that would let a
/// forged marker reach an object the caller could not otherwise open are
/// turned off, and asking for either explicitly is an error rather than a
/// silent downgrade. # C: O(1)
fn userxattr_excludes(config: &mut Config, set: OptSet) -> Result<(), Errno> {
    if set.redirect && config.redirect_mode != RedirectMode::NoFollow { return Err(Errno::Einval); }
    if config.metacopy && set.metacopy { return Err(Errno::Einval); }
    config.redirect_mode = RedirectMode::NoFollow;
    config.metacopy = false;
    Ok(())
}

/// Without privilege over `trusted.`, a feature whose markers live there
/// cannot work at all; asking for one is refused rather than pretended.
/// # C: O(1)
fn needs_trusted(config: &Config, set: OptSet) -> Result<(), Errno> {
    if set.redirect && config.redirect_mode != RedirectMode::NoFollow { return Err(Errno::Eperm); }
    if config.metacopy && set.metacopy { return Err(Errno::Eperm); }
    if config.verity_mode != VerityMode::Off { return Err(Errno::Eperm); }
    if config.nr_data() > 0 { return Err(Errno::Eperm); }
    Ok(())
}

/// Does this configuration leave the mount read-only whatever the caller
/// asked for? Writing needs both a place to put the result and a place to
/// build it. # C: O(1)
pub fn force_readonly(config: &Config) -> bool {
    config.upperdir.is_none() || config.workdir.is_none()
}

/// Is the upper layer left unsynced on purpose? # C: O(1)
pub fn volatile(config: &Config) -> bool { config.fsync_mode == FsyncMode::Volatile }
