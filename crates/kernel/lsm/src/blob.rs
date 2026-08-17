// Per-object state: how each module gets a slot of its own.
//
// A module that wants to hang state off a credential, an inode, a file or a
// socket asks for it here, once, at framework start. The framework hands back
// a region that belongs to that module alone. This is the whole point of the
// allocator: with one shared slot, the second module to attach state destroys
// the first module's, and the first module then reads the second's answer as
// its own — an access granted that its policy refuses.

/// Object kinds a module may attach state to.
///
/// One row per kind the reference contract defines, so a module porting to
/// this kernel asks for the same thing by the same name.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum BlobKind {
    Cred,
    File,
    BackingFile,
    Ib,
    Inode,
    Sock,
    Superblock,
    Ipc,
    Key,
    MsgMsg,
    PerfEvent,
    Task,
    XattrCount,
    TunDev,
    Bdev,
    BpfMap,
    BpfProg,
    BpfToken,
}

/// Number of object kinds.
pub const BLOB_KINDS: usize = 18;

/// Every kind, in the order the allocator visits them.
pub const ALL_KINDS: [BlobKind; BLOB_KINDS] = [
    BlobKind::Cred, BlobKind::File, BlobKind::BackingFile, BlobKind::Ib,
    BlobKind::Inode, BlobKind::Sock, BlobKind::Superblock, BlobKind::Ipc,
    BlobKind::Key, BlobKind::MsgMsg, BlobKind::PerfEvent, BlobKind::Task,
    BlobKind::XattrCount, BlobKind::TunDev, BlobKind::Bdev, BlobKind::BpfMap,
    BlobKind::BpfProg, BlobKind::BpfToken,
];

impl BlobKind {
    /// Index of this kind in a per-kind array. # C: O(1)
    pub const fn index(self) -> usize { self as usize }

    /// Name used in the framework's own reporting. # C: O(1)
    pub const fn name(self) -> &'static str {
        match self {
            BlobKind::Cred => "cred",
            BlobKind::File => "file",
            BlobKind::BackingFile => "backing_file",
            BlobKind::Ib => "ib",
            BlobKind::Inode => "inode",
            BlobKind::Sock => "sock",
            BlobKind::Superblock => "superblock",
            BlobKind::Ipc => "ipc",
            BlobKind::Key => "key",
            BlobKind::MsgMsg => "msg_msg",
            BlobKind::PerfEvent => "perf_event",
            BlobKind::Task => "task",
            BlobKind::XattrCount => "xattr_count",
            BlobKind::TunDev => "tun_dev",
            BlobKind::Bdev => "bdev",
            BlobKind::BpfMap => "bpf_map",
            BlobKind::BpfProg => "bpf_prog",
            BlobKind::BpfToken => "bpf_token",
        }
    }
}

/// Alignment every module's region starts on.
pub const BLOB_ALIGN: u32 = core::mem::size_of::<usize>() as u32;

/// Bytes reserved at the head of a shared inode region, ahead of the first
/// module's own state, for the deferred-free head the region is released
/// through. Two pointers: a next link and a callback.
pub const INODE_PREFIX_BYTES: u32 = 2 * BLOB_ALIGN;

/// What one module asks for, per object kind.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct BlobRequest {
    sizes: [u32; BLOB_KINDS],
}

impl BlobRequest {
    /// A module wanting no per-object state.
    pub const NONE: Self = Self { sizes: [0; BLOB_KINDS] };

    /// Ask for `bytes` of state on one object kind. # C: O(1)
    ///
    /// A count-valued kind carries a count here rather than a byte size; the
    /// allocator treats both the same way, because both are a quantity the
    /// module owns exclusively within the shared object.
    pub const fn with(mut self, kind: BlobKind, bytes: u32) -> Self {
        self.sizes[kind as usize] = bytes;
        self
    }

    /// What this module asked for on one kind. # C: O(1)
    pub const fn get(&self, kind: BlobKind) -> u32 { self.sizes[kind as usize] }

    /// Whether the module asked for anything at all. # C: O(kinds)
    pub fn is_empty(&self) -> bool { self.sizes.iter().all(|s| *s == 0) }
}

impl Default for BlobRequest {
    fn default() -> Self { Self::NONE }
}

/// One module's answer: where its region begins, and which slot index it is.
#[derive(Copy, Clone, Debug, Eq, PartialEq, Default)]
pub struct BlobGrant {
    /// Byte offset of this module's region within the shared object.
    pub offset: u32,
    /// Position of this module among those holding state on this kind.
    ///
    /// The byte offset describes a flat shared allocation; the slot index
    /// describes the same allocation when the state is a typed value rather
    /// than raw bytes. Both come from this one allocator, in one pass, so the
    /// two can never name different modules.
    pub slot: u16,
    /// Whether the module asked for this kind at all.
    pub present: bool,
}

/// Running totals across every module that has asked so far.
#[derive(Copy, Clone, Debug, Eq, PartialEq, Default)]
pub struct BlobSizes {
    totals: [u32; BLOB_KINDS],
    slots: [u16; BLOB_KINDS],
}

impl BlobSizes {
    pub const fn new() -> Self { Self { totals: [0; BLOB_KINDS], slots: [0; BLOB_KINDS] } }

    /// Total bytes a shared object of this kind must carry. # C: O(1)
    pub const fn total(&self, kind: BlobKind) -> u32 { self.totals[kind as usize] }

    /// How many modules hold state on this kind. # C: O(1)
    pub const fn slots(&self, kind: BlobKind) -> u16 { self.slots[kind as usize] }

    /// Grant one module its region on every kind it asked for. # C: O(kinds)
    ///
    /// Called once per module, in initialisation order, so a module's region
    /// depends only on the modules ordered ahead of it.
    pub fn grant(&mut self, request: &BlobRequest) -> [BlobGrant; BLOB_KINDS] {
        let mut out = [BlobGrant::default(); BLOB_KINDS];
        for kind in ALL_KINDS {
            let want = request.get(kind);
            if want == 0 { continue; }
            if kind == BlobKind::Inode && self.totals[kind.index()] == 0 {
                // The first module to want inode state pays for the shared
                // deferred-free head, so the head sits ahead of every
                // module's region rather than inside the first one's.
                self.totals[kind.index()] = INODE_PREFIX_BYTES;
            }
            let offset = align_up(self.totals[kind.index()], BLOB_ALIGN);
            self.totals[kind.index()] = offset + want;
            let slot = self.slots[kind.index()];
            self.slots[kind.index()] = slot + 1;
            out[kind.index()] = BlobGrant { offset, slot, present: true };
        }
        out
    }
}

/// Round a running total up to the alignment every region starts on. # C: O(1)
pub const fn align_up(value: u32, align: u32) -> u32 { value.next_multiple_of(align) }

#[cfg(test)]
#[path = "tests/blob.rs"]
mod tests;
