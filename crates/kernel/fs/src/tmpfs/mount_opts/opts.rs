// What a tmpfs mount-data string resolves to, and the credentials the
// privileged options are judged against.
//
// An option is honoured in one of two ways: the filesystem acts on the value,
// or it refuses the mount. `huge=` and the case-folding pair are honoured the
// second way — the only value each can be given that this filesystem could act
// on is the one that asks for nothing — so their resolved values are recorded
// here for the option string they came from, not consulted at run time. The
// quota classes and hard limits are honoured the FIRST way: `tmpfs::quota`
// brings the named classes up on the mount's superblock and every block and
// inode charge point consults the owner's ceilings.

use vmm::mempolicy::MemPolicy;

use super::limits::MAX_NR_INODES;

/// Large-folio policy for a mount's page allocations.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) enum HugeMode {
    /// Never use a large folio.
    #[default]
    Never,
    /// Always try.
    Always,
    /// Only where the folio stays within the file's size.
    WithinSize,
    /// Only where the caller advised it.
    Advise,
}

impl HugeMode {
    /// Written `huge=` value → mode; `None` for a name that is not one.
    /// # C: O(1)
    pub(crate) fn from_name(name: &str) -> Option<Self> {
        match name {
            HUGE_NEVER => Some(Self::Never),
            HUGE_ALWAYS => Some(Self::Always),
            HUGE_WITHIN_SIZE => Some(Self::WithinSize),
            HUGE_ADVISE => Some(Self::Advise),
            _ => None,
        }
    }
}

pub(crate) const HUGE_NEVER: &str = "never";
pub(crate) const HUGE_ALWAYS: &str = "always";
pub(crate) const HUGE_WITHIN_SIZE: &str = "within_size";
pub(crate) const HUGE_ADVISE: &str = "advise";

/// Quota class bits a mount's quota options select.
pub(crate) const QTYPE_MASK_USR: u32 = 1 << 0;
pub(crate) const QTYPE_MASK_GRP: u32 = 1 << 1;

/// Per-class quota hard limits a mount imposes. Zero means "no limit from the
/// mount options", which is distinct from a limit of zero — a limit of zero is
/// refused at parse time because it would deny the class everything.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct QuotaLimits {
    pub usr_block: u64,
    pub usr_inode: u64,
    pub grp_block: u64,
    pub grp_inode: u64,
}

/// The privilege facts the option parser judges the privileged options
/// against. Passed IN rather than read from the current task so the whole
/// decision surface is a pure function the hosted suite can drive.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct MountCred {
    /// The mount is being made in the initial user namespace.
    pub in_init_userns: bool,
    /// The mounter holds the administrative capability.
    pub sys_admin: bool,
}

impl MountCred {
    /// The privileged answer, used by in-kernel mounts that have no mounter.
    /// # C: O(1)
    pub(crate) const KERNEL: MountCred = MountCred { in_init_userns: true, sys_admin: true };
}

/// One tmpfs mount's resolved options. `None` means the option was not written
/// and the Linux default applies.
#[derive(Clone, Debug, Default, PartialEq)]
pub(crate) struct TmpfsOpts {
    /// `mode=` — root-inode permission bits.
    pub mode: Option<u16>,
    /// `uid=` — root-inode owner.
    pub uid: Option<u32>,
    /// `gid=` — root-inode group.
    pub gid: Option<u32>,
    /// `size=`/`nr_blocks=` — the data-page ceiling, in PAGES. The two spell
    /// the same ceiling, so they share one field and the last one written
    /// wins; keeping two would let them disagree.
    pub blocks: Option<u64>,
    /// `nr_inodes=` — the inode ceiling.
    pub inodes: Option<u64>,
    /// `huge=` — large-folio policy.
    pub huge: Option<HugeMode>,
    /// `mpol=` — NUMA allocation policy; `Some(None)` is an explicitly written
    /// DEFAULT policy, which is the absence of one.
    pub mpol: Option<Option<MemPolicy>>,
    /// `inode64` (true) / `inode32` (false) — whether inode numbers may use
    /// the full 64-bit space.
    pub full_inums: Option<bool>,
    /// `noswap` — this mount's pages may never be written to swap.
    pub noswap: bool,
    /// `quota`/`usrquota`/`grpquota` — the classes quota is requested for.
    pub quota_types: u32,
    /// The four `*_hardlimit=` ceilings.
    pub qlimits: QuotaLimits,
    /// `casefold` / `casefold=utf8-<version>`: the name encoding this instance
    /// declares. `None` is a byte-exact instance.
    pub casefold: Option<alloc::string::String>,
    /// `strict_encoding`: a name the encoding cannot represent is refused
    /// rather than stored as opaque bytes. Meaningless without an encoding,
    /// and the mount says so.
    pub strict_encoding: bool,
}

impl TmpfsOpts {
    /// Resolve the block ceiling in pages, falling back to `default_pages`.
    /// # C: O(1)
    pub(crate) fn resolve_blocks(&self, default_pages: u64) -> u64 {
        self.blocks.unwrap_or(default_pages)
    }
    /// Resolve the inode ceiling, falling back to `default_inodes`. # C: O(1)
    pub(crate) fn resolve_inodes(&self, default_inodes: u64) -> u64 {
        self.inodes.unwrap_or(default_inodes)
    }
    /// Whether inode numbers may use the full 64-bit space. Unwritten means
    /// the 32-bit-safe space, which is what a mount that never says otherwise
    /// gets so that a 32-bit `stat(2)` on its files cannot overflow. # C: O(1)
    pub(crate) fn full_inums(&self) -> bool { self.full_inums.unwrap_or(false) }
    /// Largest inode ceiling a mount may ask for. # C: O(1)
    pub(crate) const fn max_inodes() -> u64 { MAX_NR_INODES }
}
