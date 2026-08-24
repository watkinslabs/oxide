//! NTFS extended-attribute records.
//!
//! Linux ntfs3 stores POSIX ACLs in the native `$EA_INFO`/`$EA` attributes.
//! The VFS carries the version-2 interchange blob; this module owns the
//! version-1 NTFS EA record and keeps that conversion in one place.

extern crate alloc;
use alloc::vec::Vec;

use syscall::errno::Errno;
use sectors::SectorSource;

use super::{edit, Volume};
use crate::attrib;
use crate::run::Runs;
use crate::uapi::*;

const EA_INFO_SIZE: usize = 8;
const EA_HEADER_SIZE: usize = 8;
const FILE_NEED_EA: u8 = 0x80;

#[derive(Clone, Debug, Eq, PartialEq)]
struct Ea { name: Vec<u8>, flags: u8, value: Vec<u8> }

fn aligned(n: usize) -> Option<usize> { n.checked_add(3).map(|n| n & !3) }

fn decode(raw: &[u8]) -> Result<Vec<Ea>, Errno> {
    let mut out = Vec::new();
    let mut at = 0;
    while at < raw.len() {
        if raw.len() - at < EA_HEADER_SIZE { return Err(Errno::Euclean); }
        let size = u32::from_le_bytes(raw[at..at + 4].try_into().unwrap()) as usize;
        let name_len = raw[at + 5] as usize;
        let value_len = u16::from_le_bytes(raw[at + 6..at + 8].try_into().unwrap()) as usize;
        let body = EA_HEADER_SIZE.checked_add(name_len).and_then(|n| n.checked_add(1))
            .and_then(|n| n.checked_add(value_len)).ok_or(Errno::Eio)?;
        let size = if size == 0 { aligned(body).ok_or(Errno::Eio)? } else { size };
        if size < body || size & 3 != 0 || at.checked_add(size).ok_or(Errno::Eio)? > raw.len() {
            return Err(Errno::Euclean);
        }
        let name_start = at + EA_HEADER_SIZE;
        let value_start = name_start + name_len + 1;
        if raw[name_start + name_len] != 0 { return Err(Errno::Euclean); }
        out.push(Ea { name: raw[name_start..name_start + name_len].to_vec(),
                      flags: raw[at + 4], value: raw[value_start..value_start + value_len].to_vec() });
        at += size;
    }
    Ok(out)
}

pub(crate) fn value(raw: &[u8], name: &[u8]) -> Result<Option<Vec<u8>>, Errno> {
    Ok(decode(raw)?.into_iter().find(|ea| ea.name == name).map(|ea| ea.value))
}

fn encode(eas: &[Ea]) -> Result<Vec<u8>, Errno> {
    let mut out = Vec::new();
    for ea in eas {
        if ea.name.len() > u8::MAX as usize || ea.value.len() > u16::MAX as usize {
            return Err(Errno::E2big);
        }
        let body = EA_HEADER_SIZE.checked_add(ea.name.len()).and_then(|n| n.checked_add(1))
            .and_then(|n| n.checked_add(ea.value.len())).ok_or(Errno::E2big)?;
        let size = aligned(body).ok_or(Errno::E2big)?;
        let start = out.len();
        out.resize(start + size, 0);
        out[start..start + 4].copy_from_slice(&(size as u32).to_le_bytes());
        out[start + 4] = ea.flags;
        out[start + 5] = ea.name.len() as u8;
        out[start + 6..start + 8].copy_from_slice(&(ea.value.len() as u16).to_le_bytes());
        let name = start + EA_HEADER_SIZE;
        out[name..name + ea.name.len()].copy_from_slice(&ea.name);
        let value = name + ea.name.len() + 1;
        out[value..value + ea.value.len()].copy_from_slice(&ea.value);
    }
    Ok(out)
}

fn packed_size(ea: &Ea) -> Result<usize, Errno> {
    4usize.checked_add(ea.name.len()).and_then(|n| n.checked_add(1))
        .and_then(|n| n.checked_add(ea.value.len())).ok_or(Errno::E2big)
}

impl<S: SectorSource> Volume<S> {
    /// Read one native EA by its byte name. # C: O(EA bytes)
    pub fn read_ea(&self, number: u64, name: &[u8]) -> Result<Vec<u8>, Errno> {
        let (bytes, attrs) = self.read_live_record(number)?;
        let Some(attr) = attrib::find(&attrs, ATTR_EA, &[]) else { return Err(Errno::Enodata) };
        let raw = self.attribute_bytes(&bytes, &attrs, attr)?;
        decode(&raw)?.into_iter().find(|ea| ea.name == name)
            .map(|ea| ea.value).ok_or(Errno::Enodata)
    }

    /// Replace or remove one native EA. # C: O(record + EA bytes)
    pub fn write_ea(&mut self, number: u64, name: &[u8], value: Option<&[u8]>, now: i64)
        -> Result<(), Errno> {
        if !self.writable { return Err(Errno::Erofs); }
        let (mut bytes, header) = self.read_record_raw(number)?;
        let attrs = attrib::parse_all(&bytes, &header);
        let old_attr = attrib::find(&attrs, ATTR_EA, &[]).cloned();
        let old_runs = match old_attr.as_ref().map(|attr| attr.body) {
            Some(crate::attrib::Body::NonResident { .. }) =>
                self.attribute_runs(&bytes, &attrs, old_attr.as_ref().unwrap())?,
            _ => Runs::new(),
        };
        let mut eas = old_attr.as_ref()
            .map(|attr| self.attribute_bytes(&bytes, &attrs, attr))
            .transpose()?.map(|raw| decode(&raw)).transpose()?.unwrap_or_default();
        eas.retain(|ea| ea.name != name);
        if let Some(value) = value {
            eas.push(Ea { name: name.to_vec(), flags: 0, value: value.to_vec() });
        }
        let old_ea = attrib::find(&attrs, ATTR_EA, &[]).map(|a| a.offset);
        if let Some(at) = old_ea { edit::remove_at(&mut bytes, &header, at)?; }
        let header = crate::record::parse(&bytes).map_err(|e| e.errno())?;
        let attrs = attrib::parse_all(&bytes, &header);
        let info_at = attrib::find(&attrs, ATTR_EA_INFO, &[]).map(|a| a.offset);
        if let Some(at) = info_at { edit::remove_at(&mut bytes, &header, at)?; }
        let mut new_runs = Runs::new();
        if !eas.is_empty() {
            let raw = encode(&eas)?;
            let packed = eas.iter().map(packed_size).try_fold(0usize, |sum, size| {
                sum.checked_add(size?).ok_or(Errno::E2big)
            })?;
            if raw.len() > u32::MAX as usize || packed > u16::MAX as usize {
                return Err(Errno::E2big);
            }
            let mut info = [0u8; EA_INFO_SIZE];
            info[..2].copy_from_slice(&(packed as u16).to_le_bytes());
            info[2..4].copy_from_slice(&(eas.iter().filter(|ea| ea.flags & FILE_NEED_EA != 0).count() as u16).to_le_bytes());
            info[4..8].copy_from_slice(&(raw.len() as u32).to_le_bytes());
            let mut candidate = bytes.clone();
            let header = crate::record::parse(&candidate).map_err(|e| e.errno())?;
            let id = edit::take_attr_id(&mut candidate);
            edit::insert(&mut candidate, &header, &edit::resident(ATTR_EA_INFO, &[], id, false, &info))?;
            let header = crate::record::parse(&candidate).map_err(|e| e.errno())?;
            let id = edit::take_attr_id(&mut candidate);
            let resident = edit::resident(ATTR_EA, &[], id, false, &raw);
            if edit::insert(&mut candidate, &header, &resident).is_ok() {
                bytes = candidate;
            } else {
                let clusters = self.geo.clusters_for(raw.len() as u64);
                new_runs = self.alloc_clusters(clusters)?;
                let header = crate::record::parse(&bytes).map_err(|e| e.errno())?;
                let id = edit::take_attr_id(&mut bytes);
                edit::insert(&mut bytes, &header, &edit::resident(ATTR_EA_INFO, &[], id, false, &info))?;
                let header = crate::record::parse(&bytes).map_err(|e| e.errno())?;
                let id = edit::take_attr_id(&mut bytes);
                let attr = edit::non_resident(ATTR_EA, &[], id, &new_runs,
                                              new_runs.clusters() << self.geo.cluster_bits,
                                              raw.len() as u64, raw.len() as u64,
                                              self.geo.cluster_bits);
                if let Err(err) = edit::insert(&mut bytes, &header, &attr) {
                    let _ = self.free_runs(&new_runs);
                    return Err(err);
                }
                if let Err(err) = self.write_runs(&new_runs, 0, &raw) {
                    let _ = self.free_runs(&new_runs);
                    return Err(err);
                }
            }
        }
        let attrs = attrib::parse_all(&bytes, &crate::record::parse(&bytes).map_err(|e| e.errno())?);
        if let Some(std) = attrib::find(&attrs, ATTR_STD, &[]) {
            if let Some((start, end)) = std.resident_span() {
                if end - start >= SIZEOF_STD_INFO {
                    for off in [STD_OFF_M_TIME, STD_OFF_C_TIME, STD_OFF_A_TIME] {
                        bytes[start + off..start + off + 8].copy_from_slice(&(now as u64).to_le_bytes());
                    }
                }
            }
        }
        if let Err(err) = self.write_record(number, &mut bytes) {
            if !new_runs.runs.is_empty() { let _ = self.free_runs(&new_runs); }
            return Err(err);
        }
        if !old_runs.runs.is_empty() { self.free_runs(&old_runs)?; }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::{decode, encode, value, Ea};

    #[test]
    fn native_ea_records_round_trip_multiple_values() {
        let input = alloc::vec![
            Ea { name: b"system.posix_acl_access".to_vec(), flags: 0,
                value: alloc::vec![1, 2, 3] },
            Ea { name: b"$LXMOD".to_vec(), flags: 0, value: 0o640u32.to_le_bytes().to_vec() },
        ];
        let raw = encode(&input).unwrap();
        assert_eq!(decode(&raw).unwrap(), input);
        assert_eq!(value(&raw, b"$LXMOD").unwrap(), Some(0o640u32.to_le_bytes().to_vec()));
    }

    #[test]
    fn native_ea_rejects_a_truncated_value() {
        assert!(decode(&[16, 0, 0, 0, 0, 1, 4, 0, b'x']).is_err());
    }
}
