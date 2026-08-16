//! An NTFS volume built the way a formatter would.
//!
//! Independent of the reader: every structure is laid out from the format's
//! own rules, so a passing test proves the two AGREE rather than that one
//! function is self-consistent. The MFT, its mirror, `$Bitmap`, `$UpCase`,
//! `$Volume` and the root directory are all present, each in its fixed record.

use alloc::vec;
use alloc::vec::Vec;

use sectors::MemImage;

use crate::opts::Options;
use crate::record::Reference;
use crate::uapi::*;
use crate::volume::Volume;
use crate::{index, name, run, upcase};

pub const SECTOR: usize = 512;
pub const CLUSTER: usize = 4096;
pub const RECORD_SIZE: u32 = 1024;
pub const INDEX_SIZE: u32 = 4096;
pub const CLUSTERS: u64 = 512;
/// Where the MFT begins, and its mirror.
pub const MFT_LCN: u64 = 32;
pub const MFT_MIRR_LCN: u64 = 16;
/// Records the MFT holds, which is one cluster's worth per four records.
pub const MFT_RECORDS: u64 = 64;
/// Clusters the MFT itself occupies.
pub const MFT_CLUSTERS: u64 = MFT_RECORDS * RECORD_SIZE as u64 / CLUSTER as u64;
/// Where the volume's own data files sit.
pub const BITMAP_LCN: u64 = 64;
pub const UPCASE_LCN: u64 = 96;
pub const UPCASE_CLUSTERS: u64 = 32;
/// The first cluster a test file may take.
pub const FIRST_FREE_LCN: u64 = 160;

/// A volume under construction.
pub struct Builder {
    pub bytes: Vec<u8>,
    /// Directory entries written into the root's index so far.
    root_entries: Vec<Vec<u8>>,
    next_lcn: u64,
    next_record: u64,
}

impl Builder {
    /// An empty formatted volume. # C: O(image bytes)
    pub fn new() -> Self {
        let mut b = Self {
            bytes: vec![0u8; CLUSTERS as usize * CLUSTER],
            root_entries: Vec::new(),
            next_lcn: FIRST_FREE_LCN,
            next_record: MFT_REC_USER,
        };
        b.write_boot();
        b
    }

    /// Byte offset of a cluster. # C: O(1)
    pub fn cluster_at(&self, lcn: u64) -> usize { lcn as usize * CLUSTER }

    /// Byte offset of an MFT record. # C: O(1)
    pub fn record_at(&self, number: u64) -> usize {
        MFT_LCN as usize * CLUSTER + number as usize * RECORD_SIZE as usize
    }

    /// Lay out the boot sector. # C: O(1)
    fn write_boot(&mut self) {
        let b = &mut self.bytes[..BOOT_BYTES];
        b[BOOT_OFF_SYSTEM_ID..BOOT_OFF_SYSTEM_ID + 8].copy_from_slice(SYSTEM_ID.as_slice());
        b[BOOT_OFF_BYTES_PER_SECTOR] = (SECTOR & 0xFF) as u8;
        b[BOOT_OFF_BYTES_PER_SECTOR + 1] = (SECTOR >> 8) as u8;
        b[BOOT_OFF_SECTORS_PER_CLUSTER] = (CLUSTER / SECTOR) as u8;
        b[BOOT_OFF_MEDIA_TYPE] = 0xF8;
        let sectors = CLUSTERS * (CLUSTER / SECTOR) as u64;
        b[BOOT_OFF_SECTORS_PER_VOLUME..BOOT_OFF_SECTORS_PER_VOLUME + 8]
            .copy_from_slice(&sectors.to_le_bytes());
        b[BOOT_OFF_MFT_CLST..BOOT_OFF_MFT_CLST + 8].copy_from_slice(&MFT_LCN.to_le_bytes());
        b[BOOT_OFF_MFT2_CLST..BOOT_OFF_MFT2_CLST + 8]
            .copy_from_slice(&MFT_MIRR_LCN.to_le_bytes());
        // A NEGATIVE size field is a power-of-two byte count: 1024 is -10.
        b[BOOT_OFF_RECORD_SIZE] = (-10i8) as u8;
        // 4096 is -12, and could equally be one cluster written as +1.
        b[BOOT_OFF_INDEX_SIZE] = (-12i8) as u8;
        b[BOOT_OFF_SERIAL..BOOT_OFF_SERIAL + 8]
            .copy_from_slice(&0x0123_4567_89AB_CDEFu64.to_le_bytes());
        b[BOOT_BYTES - 2] = 0x55;
        b[BOOT_BYTES - 1] = 0xAA;
    }

    /// Take the next free cluster run. # C: O(1)
    pub fn alloc(&mut self, count: u64) -> u64 {
        let lcn = self.next_lcn;
        self.next_lcn += count;
        lcn
    }

    /// Take the next free record. # C: O(1)
    pub fn alloc_record(&mut self) -> u64 {
        let number = self.next_record;
        self.next_record += 1;
        number
    }

    /// Write `data` into freshly allocated clusters and return their runs.
    /// # C: O(data bytes)
    pub fn write_data(&mut self, data: &[u8]) -> run::Runs {
        let count = (data.len().div_ceil(CLUSTER)) as u64;
        let lcn = self.alloc(count.max(1));
        let at = self.cluster_at(lcn);
        self.bytes[at..at + data.len()].copy_from_slice(data);
        let mut runs = run::Runs::new();
        runs.push(run::Run { vcn: 0, lcn, len: count.max(1) });
        runs
    }

    /// Build a record with the attributes given, and stamp its update
    /// sequence. # C: O(record bytes)
    pub fn put_record(&mut self, number: u64, flags: u16, parent: &Reference,
                      attrs: &[Vec<u8>]) {
        let mut rec = crate::record::format(RECORD_SIZE, number, 1);
        crate::record::set_flags(&mut rec, RECORD_FLAG_IN_USE | flags);
        crate::record::write_reference(&mut rec, MFT_OFF_PARENT_REF, parent);
        for attr in attrs {
            let header = crate::record::parse(&rec).unwrap();
            crate::volume::edit::insert(&mut rec, &header, attr).expect("record fixture overflow");
        }
        crate::fixup::pre_write(&mut rec, 1).unwrap();
        let at = self.record_at(number);
        self.bytes[at..at + rec.len()].copy_from_slice(&rec);
        // The mirror carries the first records, which is what makes a volume
        // whose MFT head was lost still mountable.
        if number < MFT_REC_USER {
            let at = MFT_MIRR_LCN as usize * CLUSTER + number as usize * RECORD_SIZE as usize;
            self.bytes[at..at + rec.len()].copy_from_slice(&rec);
        }
    }

    /// A `$STANDARD_INFORMATION` attribute. # C: O(1)
    pub fn std_info(attributes: u32) -> Vec<u8> {
        let mut info = vec![0u8; SIZEOF_STD_INFO];
        let now = crate::time::from_unix(vfs::timespec::Timespec64::from_secs(1_700_000_000));
        for off in [STD_OFF_CR_TIME, STD_OFF_M_TIME, STD_OFF_C_TIME, STD_OFF_A_TIME] {
            info[off..off + 8].copy_from_slice(&(now as u64).to_le_bytes());
        }
        info[STD_OFF_FA..STD_OFF_FA + 4].copy_from_slice(&attributes.to_le_bytes());
        crate::volume::edit::resident(ATTR_STD, &[], 0, false, &info)
    }

    /// A `$FILE_NAME` attribute naming `name` in `parent`. # C: O(name length)
    pub fn file_name(parent: u64, name: &str, attributes: u32, size: u64) -> Vec<u8> {
        let fname = Self::fname(parent, name, attributes, size);
        crate::volume::edit::resident(ATTR_NAME, &[], 1, true, &name::write_filename(&fname))
    }

    /// The filename record a name produces. # C: O(name length)
    pub fn fname(parent: u64, name: &str, attributes: u32, size: u64) -> name::FileName {
        let now = crate::time::from_unix(vfs::timespec::Timespec64::from_secs(1_700_000_000));
        name::FileName {
            parent: Reference { number: parent, sequence: 1 },
            create_time: now,
            modify_time: now,
            change_time: now,
            access_time: now,
            alloc_size: size.next_multiple_of(CLUSTER as u64),
            data_size: size,
            attributes,
            namespace: FILE_NAME_POSIX,
            units: name.encode_utf16().collect(),
        }
    }

    /// Add a file to the root directory, with `data` as its contents.
    /// # C: O(data bytes)
    pub fn push_file(&mut self, name: &str, data: &[u8]) -> u64 {
        let number = self.alloc_record();
        let attr = if data.len() < 512 {
            crate::volume::edit::resident(ATTR_DATA, &[], 2, false, data)
        } else {
            let runs = self.write_data(data);
            crate::volume::edit::non_resident(ATTR_DATA, &[], 2, &runs, 0, data.len() as u64,
                                              data.len() as u64, CLUSTER.trailing_zeros())
        };
        let attrs = alloc::vec![
            Self::std_info(FILE_ATTRIBUTE_ARCHIVE),
            Self::file_name(MFT_REC_ROOT, name, FILE_ATTRIBUTE_ARCHIVE, data.len() as u64),
            attr,
        ];
        self.put_record(number, 0, &Reference::default(), &attrs);
        self.push_root_entry(number, name, FILE_ATTRIBUTE_ARCHIVE, data.len() as u64);
        number
    }

    /// Add a file whose data is a runlist the caller supplies, so a test can
    /// build a sparse or fragmented one. # C: O(runs)
    pub fn push_file_runs(&mut self, name: &str, runs: &run::Runs, size: u64, flags: u16,
                          c_unit: u8) -> u64 {
        let number = self.alloc_record();
        let mut attr = crate::volume::edit::non_resident(ATTR_DATA, &[], 2, runs, 0, size, size,
                                                         CLUSTER.trailing_zeros());
        attr[ATTR_OFF_FLAGS..ATTR_OFF_FLAGS + 2].copy_from_slice(&flags.to_le_bytes());
        attr[NRES_OFF_C_UNIT] = c_unit;
        let attrs = alloc::vec![
            Self::std_info(FILE_ATTRIBUTE_ARCHIVE),
            Self::file_name(MFT_REC_ROOT, name, FILE_ATTRIBUTE_ARCHIVE, size),
            attr,
        ];
        self.put_record(number, 0, &Reference::default(), &attrs);
        self.push_root_entry(number, name, FILE_ATTRIBUTE_ARCHIVE, size);
        number
    }

    /// Add an empty directory to the root. # C: O(1)
    pub fn push_dir(&mut self, name: &str) -> u64 {
        let number = self.alloc_record();
        let root = crate::volume::dirops::insert::empty_index_root(INDEX_SIZE, CLUSTER as u32);
        let attrs = alloc::vec![
            Self::std_info(FILE_ATTRIBUTE_DIRECTORY),
            Self::file_name(MFT_REC_ROOT, name, FILE_ATTRIBUTE_DIRECTORY, 0),
            crate::volume::edit::resident(ATTR_ROOT, &I30_NAME, 2, false, &root),
        ];
        self.put_record(number, RECORD_FLAG_DIR, &Reference::default(), &attrs);
        self.push_root_entry(number, name, FILE_ATTRIBUTE_DIRECTORY, 0);
        number
    }

    /// Put an entry into the root's index, keeping it in key order.
    /// # C: O(entries)
    pub fn push_root_entry(&mut self, number: u64, name: &str, attributes: u32, size: u64) {
        let fname = Self::fname(MFT_REC_ROOT, name, attributes, size);
        let key = name::write_filename(&fname);
        let entry = index::entry::build(&Reference { number, sequence: 1 }, &key, None);
        let table = upcase::builtin();
        let units: Vec<u16> = name.encode_utf16().collect();
        let mut at = self.root_entries.len();
        for (i, existing) in self.root_entries.iter().enumerate() {
            let parsed = index::entry::parse(existing, 0, ATTR_NAME).unwrap();
            let other = parsed.name().unwrap();
            if upcase::compare(&other.units, &units, &table, false) == core::cmp::Ordering::Greater {
                at = i;
                break;
            }
        }
        self.root_entries.insert(at, entry);
    }

    /// Lay out the volume's own records and finish the image.
    /// # C: O(image bytes)
    pub fn finish(mut self) -> MemImage {
        let record_bits = RECORD_SIZE.trailing_zeros();
        let _ = record_bits;

        // $MFT: its own data runlist, and the bitmap saying which records are
        // live.
        let mut mft_runs = run::Runs::new();
        mft_runs.push(run::Run { vcn: 0, lcn: MFT_LCN, len: MFT_CLUSTERS });
        let mft_bits = crate::bitmap::bytes_for(MFT_RECORDS) as usize;
        let mut mft_bitmap = vec![0u8; mft_bits];
        for number in 0..self.next_record {
            mft_bitmap[(number / 8) as usize] |= 1 << (number % 8);
        }
        let mft_data = crate::volume::edit::non_resident(
            ATTR_DATA, &[], 2, &mft_runs, MFT_CLUSTERS * CLUSTER as u64,
            MFT_RECORDS * u64::from(RECORD_SIZE), MFT_RECORDS * u64::from(RECORD_SIZE),
            CLUSTER.trailing_zeros());
        let mft_bitmap_attr = crate::volume::edit::resident(ATTR_BITMAP, &[], 3, false,
                                                            &mft_bitmap);
        self.put_record(MFT_REC_MFT, RECORD_FLAG_SYSTEM, &Reference::default(),
                        &alloc::vec![Self::std_info(FILE_ATTRIBUTE_HIDDEN), mft_data,
                                     mft_bitmap_attr]);

        // $Bitmap: one bit per cluster of the volume.
        let cluster_bytes = crate::bitmap::bytes_for(CLUSTERS) as usize;
        let mut cluster_bitmap = vec![0u8; cluster_bytes];
        for lcn in 0..self.next_lcn.min(CLUSTERS) {
            cluster_bitmap[(lcn / 8) as usize] |= 1 << (lcn % 8);
        }
        let at = self.cluster_at(BITMAP_LCN);
        self.bytes[at..at + cluster_bytes].copy_from_slice(&cluster_bitmap);
        let mut bitmap_runs = run::Runs::new();
        bitmap_runs.push(run::Run { vcn: 0, lcn: BITMAP_LCN, len: 1 });
        let bitmap_data = crate::volume::edit::non_resident(
            ATTR_DATA, &[], 2, &bitmap_runs, CLUSTER as u64, cluster_bytes as u64,
            cluster_bytes as u64, CLUSTER.trailing_zeros());
        self.put_record(MFT_REC_BITMAP, RECORD_FLAG_SYSTEM, &Reference::default(),
                        &alloc::vec![Self::std_info(FILE_ATTRIBUTE_HIDDEN), bitmap_data]);

        // $UpCase: the fold and the ordering every directory is sorted by.
        let table = upcase::pack(&upcase::builtin());
        let at = self.cluster_at(UPCASE_LCN);
        self.bytes[at..at + table.len()].copy_from_slice(&table);
        let mut upcase_runs = run::Runs::new();
        upcase_runs.push(run::Run { vcn: 0, lcn: UPCASE_LCN, len: UPCASE_CLUSTERS });
        let upcase_data = crate::volume::edit::non_resident(
            ATTR_DATA, &[], 2, &upcase_runs, UPCASE_CLUSTERS * CLUSTER as u64,
            table.len() as u64, table.len() as u64, CLUSTER.trailing_zeros());
        self.put_record(MFT_REC_UPCASE, RECORD_FLAG_SYSTEM, &Reference::default(),
                        &alloc::vec![Self::std_info(FILE_ATTRIBUTE_HIDDEN), upcase_data]);

        // $Volume: the label and the version.
        let label: Vec<u8> = "OXIDE".encode_utf16().flat_map(u16::to_le_bytes).collect();
        let mut info = vec![0u8; SIZEOF_VOLUME_INFO];
        info[VOLINFO_OFF_MAJOR] = 3;
        info[VOLINFO_OFF_MINOR] = 1;
        self.put_record(MFT_REC_VOL, RECORD_FLAG_SYSTEM, &Reference::default(),
                        &alloc::vec![
                            Self::std_info(FILE_ATTRIBUTE_HIDDEN),
                            crate::volume::edit::resident(ATTR_LABEL, &[], 2, false, &label),
                            crate::volume::edit::resident(ATTR_VOL_INFO, &[], 3, false, &info)]);

        // The root directory, whose index root holds every entry pushed.
        let root = self.build_root_index();
        self.put_record(MFT_REC_ROOT, RECORD_FLAG_DIR, &Reference::default(),
                        &alloc::vec![
                            Self::std_info(FILE_ATTRIBUTE_DIRECTORY),
                            Self::file_name(MFT_REC_ROOT, ".", FILE_ATTRIBUTE_DIRECTORY, 0),
                            crate::volume::edit::resident(ATTR_ROOT, &I30_NAME, 2, false, &root)]);

        MemImage::from_bytes(SECTOR as u32, self.bytes)
    }

    /// The root's `$INDEX_ROOT` data, entries and all. # C: O(entries)
    fn build_root_index(&self) -> Vec<u8> {
        let last = index::entry::build_last(None);
        let body: usize = self.root_entries.iter().map(|e| e.len()).sum::<usize>() + last.len();
        let node = crate::volume::dirops::insert::rebuild_node(
            &self.root_entries, &last, IROOT_OFF_IHDR, (SIZEOF_IHDR + body) as u32, 0).unwrap();
        let mut out = alloc::vec![0u8; IROOT_OFF_IHDR];
        out[IROOT_OFF_TYPE..IROOT_OFF_TYPE + 4].copy_from_slice(&ATTR_NAME.to_le_bytes());
        out[IROOT_OFF_RULE..IROOT_OFF_RULE + 4].copy_from_slice(&COLLATION_FILENAME.to_le_bytes());
        out[IROOT_OFF_BLOCK_SIZE..IROOT_OFF_BLOCK_SIZE + 4]
            .copy_from_slice(&INDEX_SIZE.to_le_bytes());
        out[IROOT_OFF_BLOCK_CLST] = (INDEX_SIZE / CLUSTER as u32) as u8;
        out.extend_from_slice(&node);
        out
    }
}

/// A mounted volume over a freshly built image. # C: O(image bytes)
pub fn mount(builder: Builder) -> Volume<MemImage> {
    let mut opts = Options::defaults();
    opts.settle();
    Volume::mount_with(builder.finish(), opts).expect("fixture must mount")
}

/// A mounted volume with nothing in it but the volume's own files.
/// # C: O(image bytes)
pub fn empty() -> Volume<MemImage> { mount(Builder::new()) }
