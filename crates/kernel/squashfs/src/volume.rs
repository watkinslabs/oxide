//! A mounted volume, driven against a medium.
//!
//! Everything the layers below decided over plain bytes is applied here to a
//! real image: the tables are read and bounded at mount, and every later
//! lookup goes through them. Nothing in this module or below it knows a VFS
//! type — that starts at `mount`.
//!
//! Module manifest:
//! - `meta`:     byte reads, metadata blocks, and the metadata byte stream.
//! - `tables`:   the index tables read at mount, and the lookups through them.
//! - `inode`:    turning an inode reference into a parsed inode.
//! - `dir`:      reading a directory, and resolving one name in it.
//! - `file`:     the block list, and reading a file's bytes.
//! - `xattr`:    extended attributes, inline and out-of-line.

use alloc::collections::BTreeMap;
use alloc::vec::Vec;

use sectors::SectorSource;
use syscall::errno::Errno;

use crate::opts::Options;
use crate::superblock::{Super, SuperError};
use crate::uapi::{INVALID_BLK, SUPER_BYTES};

pub mod meta;
pub mod tables;
pub mod inode;
pub mod dir;
pub mod file;
pub mod xattr;

pub use dir::{DirEntry, DirIndex};
pub use inode::{Fragment, Inode, Kind};
pub use meta::Cursor;

/// How many decompressed metadata blocks one volume keeps.
///
/// A directory walk re-reads the same block once per entry, and decompressing
/// it each time turns a listing into one codec run per name. The cache is
/// cleared wholesale when it fills; a mounted image never changes, so a stale
/// entry cannot exist and eviction order buys nothing.
const META_CACHE_BLOCKS: usize = 64;

/// A mounted squashfs volume.
pub struct Volume<S: SectorSource> {
    src: S,
    sb: Super,
    opts: Options,
    /// Addresses of the metadata blocks holding the uid/gid table.
    id_index: Vec<u64>,
    /// Addresses of the metadata blocks holding the fragment table.
    fragment_index: Vec<u64>,
    /// Addresses of the metadata blocks holding the inode lookup table, when
    /// the image was built exportable.
    lookup_index: Vec<u64>,
    /// Addresses of the metadata blocks holding the xattr id table.
    xattr_index: Vec<u64>,
    /// Where the xattr key/value stream itself begins.
    xattr_table: u64,
    /// How many xattr identifiers the table describes.
    xattr_ids: u32,
    cache: sync::Spinlock<BTreeMap<u64, (Vec<u8>, u64)>, sync::TaskList>,
}

/// Why a volume did not mount.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum MountError {
    /// The superblock itself is unusable.
    Super(SuperError),
    /// A table the superblock points at is not where it says, or does not
    /// describe the number of entries the superblock claims.
    Table(&'static str),
    /// The image claims more bytes than the medium can produce. Proved by
    /// asking the medium for the last byte the image claims, which is the only
    /// question a sector source can answer about its own length.
    Truncated,
    /// The medium could not be read.
    Io(Errno),
}

impl From<Errno> for MountError {
    fn from(e: Errno) -> Self { Self::Io(e) }
}

impl<S: SectorSource> Volume<S> {
    /// Apply the reference's `errors=panic` policy to a failed medium or
    /// decompression operation. Structural lookup refusals remain ordinary
    /// `EIO` results; this hook is used only by the byte-reading layers below.
    /// # C: O(1)
    pub(crate) fn read_result<T>(&self, result: Result<T, Errno>) -> Result<T, Errno> {
        match result {
            Ok(value) => Ok(value),
            Err(_) if self.opts.errors == crate::opts::Errors::Panic => panic!("squashfs read failed"),
            Err(err) => Err(err),
        }
    }

    /// Mount a volume, reading and bounding every index table.
    ///
    /// The tables are read here and not lazily because each one's validity is
    /// stated in terms of where the NEXT one starts, walking backwards from the
    /// end of the image. Checking that at first use would mean re-deriving the
    /// chain on every lookup, and a chain checked once is a chain that cannot
    /// be checked differently in two places.
    /// # C: O(table bytes)
    pub fn mount_with(src: S, opts: Options) -> Result<Self, MountError> {
        let mut head = [0u8; SUPER_BYTES];
        src.read_sectors(0, &mut head).map_err(MountError::Io)?;
        // A sector source states no length, so the medium bound is proved by
        // ASKING for the last byte the image claims: a medium that cannot
        // produce it is shorter than the image says it is. Parsing is handed
        // the unbounded case so the pure check stays testable against a stated
        // length, and the probe supplies the answer the source actually has.
        let sb = Super::parse(&head, u64::MAX).map_err(MountError::Super)?;
        let mut last = [0u8; 1];
        src.read_sectors(sb.bytes_used - 1, &mut last).map_err(|_| MountError::Truncated)?;
        let mut v = Self {
            src,
            sb,
            opts,
            id_index: Vec::new(),
            fragment_index: Vec::new(),
            lookup_index: Vec::new(),
            xattr_index: Vec::new(),
            xattr_table: INVALID_BLK,
            xattr_ids: 0,
            cache: sync::Spinlock::new(BTreeMap::new()),
        };
        v.read_index_tables()?;
        Ok(v)
    }

    /// The validated superblock. # C: O(1)
    pub fn superblock(&self) -> &Super { &self.sb }

    /// This mount's option set. # C: O(1)
    pub fn options(&self) -> &Options { &self.opts }

    /// The root inode's reference. # C: O(1)
    pub fn root_reference(&self) -> u64 { self.sb.root_inode }

    /// Whether the image carries an xattr table at all. # C: O(1)
    pub fn has_xattrs(&self) -> bool { self.xattr_ids != 0 }

    /// # C: O(1)
    fn meta_cache_get(&self, block: u64) -> Option<meta::MetaBlock> {
        let cache = self.cache.lock();
        cache.get(&block).map(|(data, next)| meta::MetaBlock { data: data.clone(), next: *next })
    }

    /// # C: O(log N), amortised O(1)
    fn meta_cache_put(&self, block: u64, data: &[u8], next: u64) {
        let mut cache = self.cache.lock();
        if cache.len() >= META_CACHE_BLOCKS { cache.clear(); }
        cache.insert(block, (data.to_vec(), next));
    }
}
