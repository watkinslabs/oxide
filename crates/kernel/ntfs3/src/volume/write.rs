//! Writing a file's bytes, and the moment its data leaves the record.
//!
//! A small file's `$DATA` is RESIDENT — its bytes are in the MFT record — and
//! a file that grows past what the record can hold becomes non-resident:
//! clusters are claimed, the bytes move into them, and the attribute is
//! rewritten as a runlist. That transition is the one this file exists for; a
//! write that only ever grows the resident form fails at the record's edge and
//! calls the volume full.

use alloc::vec;
use alloc::vec::Vec;

use syscall::errno::Errno;

use sectors::SectorSource;

use crate::attrib;
use crate::run::Runs;
use crate::uapi::*;

use super::{edit, Volume};

impl<S: SectorSource> Volume<S> {
    /// Write to a file, growing it if the write reaches past its end.
    ///
    /// Returns the file's length afterwards.
    /// # C: O(bytes written + clusters claimed)
    pub fn write_file(&mut self, number: u64, offset: u64, buf: &[u8], now: i64)
        -> Result<u64, Errno> {
        self.write_stream(number, &[], offset, buf, now)
    }

    /// Write to one of a file's streams. # C: O(bytes written)
    pub fn write_stream(&mut self, number: u64, name: &[u16], offset: u64, buf: &[u8], now: i64)
        -> Result<u64, Errno> {
        if !self.writable { return Err(Errno::Erofs); }
        let (bytes, header) = self.read_record_raw(number)?;
        if !header.in_use() { return Err(Errno::Enoent); }
        if header.is_dir() { return Err(Errno::Eisdir); }
        let attrs = attrib::parse_all(&bytes, &header);
        let attr = attrib::find(&attrs, ATTR_DATA, name).ok_or(Errno::Enoent).cloned()?;
        // Encrypted bytes have no owner here; native LZNT compression does.
        if attr.encrypted() { return Err(Errno::Eopnotsupp); }
        let end = offset.checked_add(buf.len() as u64).ok_or(Errno::Efbig)?;
        let old_size = attr.data_size();
        let size = core::cmp::max(old_size, end);

        if attr.compressed() {
            let mut data = self.attribute_bytes(&bytes, &attrs, &attr)?;
            data.resize(size as usize, 0);
            data[offset as usize..offset as usize + buf.len()].copy_from_slice(buf);
            return self.rewrite_compressed(number, name, &attr, data, now);
        }

        if !attr.non_resident {
            let mut data = self.attribute_bytes(&bytes, &attrs, &attr)?;
            let fits = {
                let free = edit::free_space(&bytes, &header) + attr.size as usize;
                let want = SIZEOF_RESIDENT + name.len() * 2;
                (want.next_multiple_of(8) + size as usize).next_multiple_of(8) <= free
            };
            if fits {
                data.resize(size as usize, 0);
                data[offset as usize..offset as usize + buf.len()].copy_from_slice(buf);
                self.replace_data(number, name, attr.offset, attr.id, &data, None, size, now, 0)?;
                return Ok(size);
            }
            // The record cannot hold it: the attribute becomes non-resident,
            // and the bytes it already held move into the clusters.
            data.resize(size as usize, 0);
            data[offset as usize..offset as usize + buf.len()].copy_from_slice(buf);
            let clusters = self.geo.clusters_for(size);
            let runs = self.alloc_clusters(clusters)?;
            self.write_runs(&runs, 0, &data)?;
            self.replace_data(number, name, attr.offset, attr.id, &[], Some(runs), size, now, 0)?;
            return Ok(size);
        }

        let mut runs = self.attribute_runs(&bytes, &attrs, &attr)?;
        if attr.sparse() {
            return self.write_sparse(number, name, &attr, runs, offset, buf, old_size, end, now);
        }
        let have = runs.clusters() << self.geo.cluster_bits;
        if end > have {
            let more = self.geo.clusters_for(end) - runs.clusters();
            let extra = self.alloc_clusters(more)?;
            let base = runs.clusters();
            for mut r in extra.runs { r.vcn += base; runs.push(r); }
        }
        // The gap between the old end and this write is zeroed before the
        // write lands, so a reader of it never sees the clusters' old
        // contents.
        if offset > old_size { self.zero_span(&runs, old_size, offset - old_size)?; }
        self.write_runs(&runs, offset, buf)?;
        self.replace_data(number, name, attr.offset, attr.id, &[], Some(runs), size, now, 0)?;
        Ok(size)
    }

    /// Write a sparse stream, allocating only the clusters touched by bytes.
    /// # C: O(bytes written + clusters touched + runs)
    fn write_sparse(&mut self, number: u64, name: &[u16], attr: &attrib::Attribute,
                    mut runs: Runs, offset: u64, buf: &[u8], old_size: u64, end: u64,
                    now: i64) -> Result<u64, Errno> {
        let per = u64::from(self.geo.cluster_size);
        let covered = core::cmp::max(runs.clusters(), self.geo.clusters_for(end));
        if runs.clusters() < covered {
            runs.push(crate::run::Run { vcn: runs.clusters(), lcn: SPARSE_LCN,
                                        len: covered - runs.clusters() });
        }

        let first = offset / per;
        let last = (end - 1) / per;
        let mut missing = Vec::new();
        for vcn in first..=last {
            if matches!(runs.lookup(vcn), Some(SPARSE_LCN) | None) { missing.push(vcn); }
        }
        let extra = self.alloc_clusters(missing.len() as u64)?;
        let mut physical = Vec::new();
        for run in extra.runs {
            if run.is_hole() { return Err(Errno::Eio); }
            for i in 0..run.len { physical.push(run.lcn + i); }
        }
        if physical.len() != missing.len() { return Err(Errno::Eio); }

        let mut rebuilt = Runs::new();
        for vcn in 0..covered {
            let lcn = match runs.lookup(vcn) {
                Some(SPARSE_LCN) | None => {
                    if let Some(at) = missing.iter().position(|wanted| *wanted == vcn) {
                        physical[at]
                    } else { SPARSE_LCN }
                }
                Some(lcn) => lcn,
            };
            rebuilt.push(crate::run::Run { vcn, lcn, len: 1 });
        }
        runs = rebuilt;

        if offset > old_size {
            let zeros = vec![0u8; self.geo.cluster_size as usize];
            let mut pos = old_size;
            while pos < offset {
                let vcn = pos / per;
                let take = core::cmp::min(per - pos % per, offset - pos);
                if runs.lookup(vcn) != Some(SPARSE_LCN) {
                    self.write_runs(&runs, pos, &zeros[..take as usize])?;
                }
                pos += take;
            }
        }
        self.write_runs(&runs, offset, buf)?;
        self.replace_data(number, name, attr.offset, attr.id, &[], Some(runs),
                          core::cmp::max(old_size, end), now, attr.flags)?;
        Ok(core::cmp::max(old_size, end))
    }

    /// Set a file's length, in either direction. # C: O(clusters changed)
    pub fn truncate_file(&mut self, number: u64, len: u64, now: i64) -> Result<(), Errno> {
        if !self.writable { return Err(Errno::Erofs); }
        let (bytes, header) = self.read_record_raw(number)?;
        if header.is_dir() { return Err(Errno::Eisdir); }
        let attrs = attrib::parse_all(&bytes, &header);
        let attr = attrib::find(&attrs, ATTR_DATA, &[]).ok_or(Errno::Enoent).cloned()?;
        if attr.encrypted() { return Err(Errno::Eopnotsupp); }
        let old = attr.data_size();
        if len == old { return Ok(()); }

        if attr.compressed() {
            let mut data = self.attribute_bytes(&bytes, &attrs, &attr)?;
            data.resize(len as usize, 0);
            return self.rewrite_compressed(number, &[], &attr, data, now).map(|_| ());
        }

        if !attr.non_resident {
            let mut data = self.attribute_bytes(&bytes, &attrs, &attr)?;
            if len > old {
                // Growing a resident attribute past the record goes through
                // the write path, which knows how to move it out.
                let pad = vec![0u8; (len - old) as usize];
                self.write_file(number, old, &pad, now)?;
                return Ok(());
            }
            data.truncate(len as usize);
            return self.replace_data(number, &[], attr.offset, attr.id, &data, None, len, now, 0);
        }

        let mut runs = self.attribute_runs(&bytes, &attrs, &attr)?;
        if len > old {
            let need = self.geo.clusters_for(len);
            if attr.sparse() {
                if need > runs.clusters() {
                    runs.push(crate::run::Run { vcn: runs.clusters(), lcn: SPARSE_LCN,
                                                len: need - runs.clusters() });
                }
            } else if need > runs.clusters() {
                let extra = self.alloc_clusters(need - runs.clusters())?;
                let base = runs.clusters();
                for mut r in extra.runs { r.vcn += base; runs.push(r); }
            }
            if !attr.sparse() { self.zero_span(&runs, old, len - old)?; }
        } else {
            let keep = self.geo.clusters_for(len);
            let mut kept = Runs::new();
            let mut dropped = Runs::new();
            for run in &runs.runs {
                if run.vcn >= keep { dropped.push(*run); continue; }
                if run.vcn + run.len <= keep { kept.push(*run); continue; }
                let split = keep - run.vcn;
                kept.push(crate::run::Run { vcn: run.vcn, lcn: run.lcn, len: split });
                dropped.push(crate::run::Run {
                    vcn: run.vcn + split,
                    lcn: if run.is_hole() { SPARSE_LCN } else { run.lcn + split },
                    len: run.len - split,
                });
            }
            self.free_runs(&dropped)?;
            runs = kept;
        }
        self.replace_data(number, &[], attr.offset, attr.id, &[], Some(runs), len, now,
                          attr.flags)
    }

    /// Replace a record's `$DATA` attribute, resident or not. # C: O(record bytes)
    #[allow(clippy::too_many_arguments)]
    fn replace_data(&mut self, number: u64, name: &[u16], at: usize, id: u16, resident: &[u8],
                    runs: Option<Runs>, size: u64, now: i64, flags: u16) -> Result<(), Errno> {
        let (mut bytes, header) = self.read_record_raw(number)?;
        let attr = match &runs {
            None => edit::resident(ATTR_DATA, name, id, false, resident),
            Some(runs) => edit::non_resident_flags(ATTR_DATA, name, id, runs,
                                                   runs.clusters() << self.geo.cluster_bits,
                                                   size, size, self.geo.cluster_bits, flags),
        };
        edit::replace_at(&mut bytes, &header, at, &attr)?;
        // The length also lives in the record's own `$STANDARD_INFORMATION`
        // times and in the parent's index entry; the times are stamped here
        // and the index entry's copy is refreshed by whoever renames.
        let attrs = attrib::parse_all(&bytes, &header);
        if let Some(std) = attrib::find(&attrs, ATTR_STD, &[]) {
            if let Some((start, end)) = std.resident_span() {
                if end <= bytes.len() && end - start >= SIZEOF_STD_INFO {
                    for off in [STD_OFF_M_TIME, STD_OFF_C_TIME, STD_OFF_A_TIME] {
                        let a = start + off;
                        bytes[a..a + 8].copy_from_slice(&(now as u64).to_le_bytes());
                    }
                }
            }
        }
        self.write_record(number, &mut bytes)
    }

    /// Re-encode a native compressed stream one 64-KiB frame at a time.
    /// # C: O(file bytes * LZNT window + allocated clusters)
    fn rewrite_compressed(&mut self, number: u64, name: &[u16], attr: &attrib::Attribute,
                          data: Vec<u8>, now: i64) -> Result<u64, Errno> {
        let old_runs = if attr.non_resident {
            let (bytes, attrs) = self.read_record(number)?;
            self.attribute_runs(&bytes, &attrs, attr)?
        } else { Runs::new() };
        let unit = 1u64 << LZNT_CUNIT;
        let frame_bytes = unit << self.geo.cluster_bits;
        let mut runs = Runs::new();
        for (index, source) in data.chunks(frame_bytes as usize).enumerate() {
            let mut frame = vec![0u8; frame_bytes as usize];
            frame[..source.len()].copy_from_slice(source);
            let vcn = index as u64 * unit;
            if frame.iter().all(|byte| *byte == 0) {
                runs.push(crate::run::Run { vcn, lcn: SPARSE_LCN, len: unit });
                continue;
            }
            let packed = crate::lznt::compress(&frame);
            let full = packed.len() + self.geo.cluster_size as usize > frame.len();
            let stored = if full { frame } else { packed };
            let clusters = if full { unit } else {
                self.geo.clusters_for(stored.len() as u64)
            };
            let extra = self.alloc_clusters(clusters)?;
            let mut shifted = Runs::new();
            for mut run in extra.runs { run.vcn += vcn; shifted.push(run); }
            let mut on_disk = vec![0u8; (clusters << self.geo.cluster_bits) as usize];
            on_disk[..stored.len()].copy_from_slice(&stored);
            self.write_runs(&shifted, vcn << self.geo.cluster_bits, &on_disk)?;
            for run in shifted.runs { runs.push(run); }
            if clusters < unit {
                runs.push(crate::run::Run { vcn: vcn + clusters, lcn: SPARSE_LCN,
                                            len: unit - clusters });
            }
        }
        self.replace_data(number, name, attr.offset, attr.id, &[], Some(runs),
                          data.len() as u64, now, ATTR_FLAG_COMPRESSED)?;
        self.free_runs(&old_runs)?;
        Ok(data.len() as u64)
    }

    /// Fill a span of a runlist with zeros. # C: O(len)
    pub(crate) fn zero_span(&self, runs: &Runs, offset: u64, len: u64) -> Result<(), Errno> {
        let per = usize::try_from(self.geo.cluster_size).map_err(|_| Errno::Einval)?;
        let zeros = vec![0u8; per];
        let mut done = 0u64;
        while done < len {
            let take = core::cmp::min(per as u64, len - done);
            self.write_runs(runs, offset + done, &zeros[..take as usize])?;
            done += take;
        }
        Ok(())
    }
}
