//! What a mount was asked for.
//!
//! Every field here changes observable behaviour, and several of them change
//! what gets WRITTEN into the upper layer — a layer built by a mount with
//! `metacopy=on` is not readable by a mount without it. So the set is carried
//! whole from parse through verification to the mounted filesystem, and the
//! defaults are the build's, not each call site's guess.

extern crate alloc;

use alloc::string::String;
use alloc::vec::Vec;

/// Whether a renamed directory leaves a pointer to where its lower half lives,
/// and whether one left by someone else is believed.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum RedirectMode {
    /// Never write one; follow one already present.
    Follow,
    /// Never write one; refuse to follow one already present. An untrusted
    /// upper layer cannot use a redirect to reach a lower object the caller
    /// could not otherwise open.
    NoFollow,
    /// Write one on directory rename, and follow one present.
    On,
}

/// What `uuid=` does with the layer identifier stamped into origin handles.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum UuidMode { Off, Null, Auto, On }

/// Whether lower inode numbers get remapped into one address space.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum XinoMode { Off, Auto, On }

/// How strictly a metacopy file's recorded data digest is enforced.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum VerityMode { Off, On, Require }

/// When the upper layer is flushed.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum FsyncMode {
    /// Never — the upper layer is discarded after a crash, and a marker is
    /// left so the next mount knows not to trust it.
    Volatile,
    /// On data copy-up only.
    Auto,
    /// After every copy-up, metadata included.
    Strict,
}

/// Which of `lowerdir=`, `lowerdir+=` and `datadir+=` named a layer. The
/// distinction outlives parsing: a data-only layer is reachable only by an
/// absolute redirect, never by walking a name.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum LayerOpt {
    /// `lowerdir=` — the whole colon-separated list, replacing any prior one.
    Lowerdir,
    /// `lowerdir+=` — one more merged layer, appended.
    LowerdirAdd,
    /// `datadir+=` — one more data-only layer, appended.
    DatadirAdd,
    /// `upperdir=`.
    Upperdir,
    /// `workdir=`.
    Workdir,
}

impl LayerOpt {
    /// Does this option name the writable side of the mount? # C: O(1)
    pub fn is_upper(self) -> bool { matches!(self, LayerOpt::Upperdir | LayerOpt::Workdir) }
}

/// One lower layer as the mount named it.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct LowerName {
    /// Path exactly as it will be shown back in the mount options.
    pub name: String,
    /// Data-only layers hold file contents only; no name resolves into them.
    pub data_only: bool,
}

/// Build defaults, before any option is read. Each mirrors a build-time
/// choice: redirects are followed but not written, no index, no NFS export,
/// no inode-number remapping, no metadata-only copy-up.
pub const DEF_REDIRECT: RedirectMode = RedirectMode::Follow;
pub const DEF_INDEX: bool = false;
pub const DEF_UUID: UuidMode = UuidMode::Auto;
pub const DEF_NFS_EXPORT: bool = false;
pub const DEF_XINO: XinoMode = XinoMode::Off;
pub const DEF_METACOPY: bool = false;
pub const DEF_VERITY: VerityMode = VerityMode::Off;
pub const DEF_FSYNC: FsyncMode = FsyncMode::Auto;

/// The whole option set of one mount.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Config {
    /// Writable layer, absent on a read-only overlay.
    pub upperdir: Option<String>,
    /// Scratch directory on the same filesystem as `upperdir`.
    pub workdir: Option<String>,
    /// Lower layers, topmost first.
    pub lowerdirs: Vec<LowerName>,
    /// Verbatim `lowerdir=` string, kept so the mount shows back what it was
    /// given rather than a re-joined approximation.
    pub lowerdir_all: Option<String>,
    /// Permission is decided on the overlay inode rather than deferred to the
    /// layer that holds the object.
    pub default_permissions: bool,
    pub redirect_mode: RedirectMode,
    pub index: bool,
    pub uuid: UuidMode,
    pub nfs_export: bool,
    pub xino: XinoMode,
    pub metacopy: bool,
    /// Private markers live in `user.overlay.` instead of `trusted.overlay.`,
    /// so an unprivileged mount can write them.
    pub userxattr: bool,
    pub verity_mode: VerityMode,
    pub fsync_mode: FsyncMode,
    /// `nooverride_creds` cleared the recorded mounter credentials, so every
    /// access to a layer is made as the caller rather than as the mounter.
    pub override_creds: bool,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            upperdir: None, workdir: None, lowerdirs: Vec::new(), lowerdir_all: None,
            default_permissions: false,
            redirect_mode: DEF_REDIRECT, index: DEF_INDEX, uuid: DEF_UUID,
            nfs_export: DEF_NFS_EXPORT, xino: DEF_XINO, metacopy: DEF_METACOPY,
            userxattr: false, verity_mode: DEF_VERITY, fsync_mode: DEF_FSYNC,
            override_creds: true,
        }
    }
}

impl Config {
    /// Count of data-only layers at the bottom of the stack. # C: O(layers)
    pub fn nr_data(&self) -> usize { self.lowerdirs.iter().filter(|l| l.data_only).count() }
    /// Count of layers a name can be looked up in. # C: O(layers)
    pub fn nr_merged_lower(&self) -> usize { self.lowerdirs.len() - self.nr_data() }
    /// Is a redirect written on directory rename? # C: O(1)
    pub fn redirect_dir(&self) -> bool { self.redirect_mode == RedirectMode::On }
    /// Is a redirect found on a layer believed? # C: O(1)
    pub fn redirect_follow(&self) -> bool { self.redirect_mode != RedirectMode::NoFollow }
    /// Does an origin handle carry the layer's UUID? # C: O(1)
    pub fn origin_uuid(&self) -> bool { self.uuid != UuidMode::Off }
    /// Does the overlay present a filesystem id of its own? # C: O(1)
    pub fn has_fsid(&self) -> bool { matches!(self.uuid, UuidMode::On | UuidMode::Auto) }
    /// Is the upper layer flushed at all? # C: O(1)
    pub fn should_sync(&self) -> bool { self.fsync_mode != FsyncMode::Volatile }
    /// Is metadata flushed too, not just data? # C: O(1)
    pub fn should_sync_metadata(&self) -> bool { self.fsync_mode == FsyncMode::Strict }
    /// Is the upper layer disposable after a crash? # C: O(1)
    pub fn is_volatile(&self) -> bool { self.fsync_mode == FsyncMode::Volatile }
    /// Warn when a lower inode number will not fit the remapped space? # C: O(1)
    pub fn xino_warn(&self) -> bool { self.xino == XinoMode::On }
    /// May a layer be changed while it is mounted here? Only when none of the
    /// features that record cross-layer state are on — each of them caches a
    /// fact about a layer that an offline edit would invalidate. # C: O(1)
    pub fn allow_offline_changes(&self) -> bool {
        !self.index && !self.metacopy && !self.redirect_dir() && !self.xino_warn()
    }
    /// Prefix the private markers are written under. # C: O(1)
    pub fn xattr_prefix(&self) -> &'static str {
        if self.userxattr { crate::uapi::XATTR_USER_PREFIX } else { crate::uapi::XATTR_TRUSTED_PREFIX }
    }
}

/// Which options the mount named EXPLICITLY. Verification resolves conflicts
/// differently depending on whether a value was asked for or merely defaulted:
/// two explicit options that contradict are an error, an explicit one against
/// a default silently wins.
#[derive(Clone, Copy, Default, PartialEq, Eq, Debug)]
pub struct OptSet {
    pub metacopy: bool,
    pub redirect: bool,
    pub nfs_export: bool,
    pub index: bool,
}
