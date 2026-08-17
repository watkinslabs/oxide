//! `segment_info` and `segment_bits` — the segment table, rendered.
//!
//! Both walk every main-area segment. `segment_info` gives ten per line, each
//! `type|valid_blocks`; `segment_bits` gives one per line and adds the whole
//! validity bitmap and the segment's timestamp. The two formats are what the
//! tools that read these files expect, down to the column widths, so they are
//! built from the same table rather than from two descriptions of it.

use alloc::format;
use alloc::string::String;
use alloc::sync::Arc;

use syscall::errno::Errno;

use crate::fsattr::Attr;
use crate::mount::{errno_to_vfs, F2fs};
use crate::summary::SitEntry;
use crate::uapi::SIT_VBLOCK_MAP_SIZE;

use crate::sysfs::volume::Vol;

/// Entries per line in `segment_info`.
const PER_LINE: u32 = 10;

/// The header both files carry, naming the six segment types by number.
const TYPE_LEGEND: &str = "segment_type(0:HD, 1:WD, 2:CD, 3:HN, 4:WN, 5:CN)\n";

/// Every main-area segment's entry, table first and journal on top of it.
///
/// The table is loaded whole rather than read a segment at a time: a listing
/// of thousands of segments would otherwise be thousands of medium reads, and
/// a table that changed part-way through would splice two states into one
/// report.
/// # C: O(main segments), plus the table read on the first call
fn table(v: &mut Vol) -> Result<(u32, alloc::vec::Vec<SitEntry>), Errno> {
    v.load_segments()?;
    let n = v.super_block().segment_count_main;
    let mut out = alloc::vec::Vec::with_capacity(n as usize);
    for segno in 0..n { out.push(v.seg_entry(segno)?); }
    Ok((n, out))
}

/// `segment_info`: ten segments per line, each `type|valid_blocks`.
/// # C: O(main segments)
pub fn segment_info_body(n: u32, entries: &[SitEntry]) -> String {
    let mut s = String::from("format: segment_type|valid_blocks\n");
    s.push_str(TYPE_LEGEND);
    for i in 0..n {
        let e = match entries.get(i as usize) { Some(e) => e, None => break };
        if i % PER_LINE == 0 { s.push_str(&format!("{:<10}", i)); }
        s.push_str(&format!("{}|{:<3}", e.seg_type(), e.valid_blocks()));
        if i % PER_LINE == PER_LINE - 1 || i == n - 1 { s.push('\n'); } else { s.push(' '); }
    }
    s
}

/// `segment_bits`: one segment per line, with its whole validity bitmap and
/// its timestamp. # C: O(main segments * bitmap bytes)
pub fn segment_bits_body(n: u32, entries: &[SitEntry]) -> String {
    let mut s = String::from("format: segment_type|valid_blocks|bitmaps|mtime\n");
    s.push_str(TYPE_LEGEND);
    for i in 0..n {
        let e = match entries.get(i as usize) { Some(e) => e, None => break };
        s.push_str(&format!("{:<10}", i));
        s.push_str(&format!("{}|{:<3}|", e.seg_type(), e.valid_blocks()));
        for j in 0..SIT_VBLOCK_MAP_SIZE { s.push_str(&format!(" {:02x}", e.valid_map[j])); }
        s.push_str(&format!("| {:x}\n", e.mtime));
    }
    s
}

/// # C: O(main segments)
pub(crate) fn info_file(fs: &Arc<F2fs>, dev: &str) -> Attr {
    let fs = Arc::clone(fs);
    Attr::ro(dev, "segment_info", Arc::new(move || {
        let (n, e) = { let mut v = fs.volume.lock(); table(&mut v).map_err(errno_to_vfs)? };
        Ok(segment_info_body(n, &e).into_bytes())
    }))
}

/// # C: O(main segments * bitmap bytes)
pub(crate) fn bits_file(fs: &Arc<F2fs>, dev: &str) -> Attr {
    let fs = Arc::clone(fs);
    Attr::ro(dev, "segment_bits", Arc::new(move || {
        let (n, e) = { let mut v = fs.volume.lock(); table(&mut v).map_err(errno_to_vfs)? };
        Ok(segment_bits_body(n, &e).into_bytes())
    }))
}
