//! What one record adds up to: its type, its length, its times, its streams.
//!
//! A record has no fields of its own — everything is an attribute — so this is
//! where the attributes are turned back into the thing a caller asked about.

use alloc::string::String;
use alloc::vec::Vec;

use syscall::errno::Errno;

use sectors::SectorSource;

use crate::attrib::{self, Attribute};
use crate::name::FileName;
use crate::uapi::*;

use super::Volume;

/// What a record is.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct NodeInfo {
    pub number: u64,
    pub sequence: u16,
    pub is_dir: bool,
    pub hard_links: u16,
    /// The unnamed `$DATA` attribute's length, or zero for a directory.
    pub size: u64,
    /// Clusters the unnamed data occupies, which a sparse or compressed file
    /// has fewer of than its length implies.
    pub allocated: u64,
    pub attributes: u32,
    pub create_time: i64,
    pub modify_time: i64,
    pub change_time: i64,
    pub access_time: i64,
    /// The reparse tag, when the record carries one.
    pub reparse_tag: Option<u32>,
    /// Names of the alternate data streams beside the file's own data.
    pub streams: Vec<String>,
}

impl NodeInfo {
    /// Whether the record refuses writes. # C: O(1)
    pub fn read_only(&self) -> bool { self.attributes & FILE_ATTRIBUTE_READONLY != 0 }

    /// Whether the record is a reparse point — a symbolic link, a junction, or
    /// something this implementation does not follow. # C: O(1)
    pub fn is_reparse(&self) -> bool { self.reparse_tag.is_some() }

    /// Whether the record's data is compressed on the medium. # C: O(1)
    pub fn compressed(&self) -> bool { self.attributes & FILE_ATTRIBUTE_COMPRESSED != 0 }

    /// Whether the record's data may have holes. # C: O(1)
    pub fn sparse(&self) -> bool { self.attributes & FILE_ATTRIBUTE_SPARSE_FILE != 0 }
}

/// Read one 32-bit field. # C: O(1)
fn le32(bytes: &[u8], at: usize) -> u32 {
    u32::from_le_bytes([bytes[at], bytes[at + 1], bytes[at + 2], bytes[at + 3]])
}

/// Read one 64-bit field. # C: O(1)
fn le64(bytes: &[u8], at: usize) -> u64 {
    let mut out = [0u8; 8];
    out.copy_from_slice(&bytes[at..at + 8]);
    u64::from_le_bytes(out)
}

impl<S: SectorSource> Volume<S> {
    /// What record `number` is. # C: O(record bytes)
    pub fn stat(&self, number: u64) -> Result<NodeInfo, Errno> {
        let (bytes, header) = self.read_record_raw(number)?;
        if !header.in_use() { return Err(Errno::Enoent); }
        let attrs = attrib::parse_all(&bytes, &header);
        self.stat_from(number, &header, &bytes, &attrs)
    }

    /// What a record already read adds up to. # C: O(attributes)
    pub fn stat_from(&self, number: u64, header: &crate::record::RecordHeader, bytes: &[u8],
                     attrs: &[Attribute]) -> Result<NodeInfo, Errno> {
        let std = attrib::find(attrs, ATTR_STD, &[]).ok_or(Errno::Eio)?;
        let (start, end) = std.resident_span().ok_or(Errno::Eio)?;
        if end > bytes.len() || end - start < SIZEOF_STD_INFO { return Err(Errno::Eio); }
        let info = &bytes[start..end];

        let data = attrib::find(attrs, ATTR_DATA, &[]);
        let size = data.map_or(0, |a| a.data_size());
        let allocated = data.map_or(0, |a| match a.body {
            crate::attrib::Body::NonResident { alloc_size, total_size, .. } =>
                if a.compressed() || a.sparse() { total_size } else { alloc_size },
            crate::attrib::Body::Resident { data_size, .. } =>
                u64::from(data_size).next_multiple_of(8),
        });

        let mut attributes = le32(info, STD_OFF_FA);
        if header.is_dir() { attributes |= FILE_ATTRIBUTE_DIRECTORY; }

        let reparse_tag = attrib::find(attrs, ATTR_REPARSE, &[])
            .and_then(|a| self.attribute_bytes(bytes, attrs, a).ok())
            .filter(|raw| raw.len() >= 4)
            .map(|raw| le32(&raw, REPARSE_OFF_TAG));

        let streams = attrib::names_of(attrs, ATTR_DATA).into_iter()
            .filter(|n| !n.is_empty())
            .map(|n| crate::name::decode(&n))
            .collect();

        Ok(NodeInfo {
            number,
            sequence: header.sequence,
            is_dir: header.is_dir(),
            hard_links: header.hard_links,
            size,
            allocated,
            attributes,
            create_time: le64(info, STD_OFF_CR_TIME) as i64,
            modify_time: le64(info, STD_OFF_M_TIME) as i64,
            change_time: le64(info, STD_OFF_C_TIME) as i64,
            access_time: le64(info, STD_OFF_A_TIME) as i64,
            reparse_tag,
            streams,
        })
    }

    /// Every `$FILE_NAME` record one MFT record carries. # C: O(attributes)
    pub fn names_of(&self, bytes: &[u8], attrs: &[Attribute]) -> Vec<FileName> {
        attrs.iter()
            .filter(|a| a.ty == ATTR_NAME)
            .filter_map(|a| {
                let (start, end) = a.resident_span()?;
                if end > bytes.len() { return None; }
                crate::name::parse_filename(&bytes[start..end])
            })
            .collect()
    }

    /// Read a file's bytes. # C: O(bytes read)
    pub fn read_file(&self, number: u64, offset: u64, buf: &mut [u8]) -> Result<usize, Errno> {
        self.read_stream(number, &[], offset, buf)
    }

    /// Read one of a file's streams — its own data when `name` is empty, an
    /// alternate one otherwise. # C: O(bytes read)
    pub fn read_stream(&self, number: u64, name: &[u16], offset: u64, buf: &mut [u8])
        -> Result<usize, Errno> {
        let (bytes, attrs) = self.read_live_record(number)?;
        let attr = attrib::find(&attrs, ATTR_DATA, name).ok_or(Errno::Enoent)?;
        self.read_attribute(&bytes, &attrs, attr, offset, buf)
    }

    /// Read the complete named data stream. # C: O(stream bytes)
    pub fn read_stream_whole(&self, number: u64, name: &[u16]) -> Result<Vec<u8>, Errno> {
        let (bytes, attrs) = self.read_live_record(number)?;
        let attr = attrib::find(&attrs, ATTR_DATA, name).ok_or(Errno::Enoent)?;
        self.attribute_bytes(&bytes, &attrs, attr)
    }

    /// The whole of a file. # C: O(file bytes)
    pub fn read_whole(&self, number: u64) -> Result<Vec<u8>, Errno> {
        let (bytes, attrs) = self.read_live_record(number)?;
        let attr = attrib::find(&attrs, ATTR_DATA, &[]).ok_or(Errno::Enoent)?;
        self.attribute_bytes(&bytes, &attrs, attr)
    }

    /// Where a symbolic link or junction points.
    ///
    /// The two carry their target differently and both are read: a junction
    /// has no print name of its own, and a symbolic link's target may be
    /// relative to the link.
    /// # C: O(reparse bytes)
    pub fn read_link(&self, number: u64) -> Result<String, Errno> {
        let (bytes, attrs) = self.read_live_record(number)?;
        let attr = attrib::find(&attrs, ATTR_REPARSE, &[]).ok_or(Errno::Einval)?;
        let raw = self.attribute_bytes(&bytes, &attrs, attr)?;
        if raw.len() < REPARSE_OFF_MOUNT_BUFFER { return Err(Errno::Eio); }
        let tag = le32(&raw, REPARSE_OFF_TAG);
        let field = |at: usize| usize::from(u16::from_le_bytes([raw[at], raw[at + 1]]));
        let (start, len) = match tag {
            IO_REPARSE_TAG_SYMLINK => {
                let off = field(REPARSE_OFF_SYMLINK_PRINT_OFF);
                (REPARSE_OFF_SYMLINK_BUFFER.checked_add(off).ok_or(Errno::Eio)?,
                 field(REPARSE_OFF_SYMLINK_PRINT_LEN))
            }
            IO_REPARSE_TAG_MOUNT_POINT => {
                let off = field(REPARSE_OFF_SYMLINK_SUB_OFF);
                (REPARSE_OFF_MOUNT_BUFFER.checked_add(off).ok_or(Errno::Eio)?,
                 field(REPARSE_OFF_SYMLINK_SUB_LEN))
            }
            tag if tag & IO_REPARSE_TAG_NAME_SURROGATE != 0
                && tag & IO_REPARSE_TAG_MICROSOFT == 0 => {
                if raw.len() < REPARSE_OFF_GENERIC_BUFFER { return Err(Errno::Eio); }
                let declared = usize::from(u16::from_le_bytes([
                    raw[REPARSE_OFF_DATA_LEN], raw[REPARSE_OFF_DATA_LEN + 1],
                ]));
                let len = declared.checked_sub(REPARSE_OFF_GENERIC_BUFFER)
                    .ok_or(Errno::Eio)?;
                (REPARSE_OFF_GENERIC_BUFFER, len)
            }
            // A tag this implementation does not know is not a link, and
            // following it as one would produce a path from arbitrary bytes.
            _ => return Err(Errno::Einval),
        };
        let stop = start.checked_add(len).ok_or(Errno::Eio)?;
        if stop > raw.len() { return Err(Errno::Eio); }
        let units: Vec<u16> = raw[start..stop].chunks_exact(2)
            .map(|p| u16::from_le_bytes([p[0], p[1]])).collect();
        Ok(crate::name::decode(&units).replace('\\', "/"))
    }
}
