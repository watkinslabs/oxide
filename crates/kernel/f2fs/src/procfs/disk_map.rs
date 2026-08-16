//! `disk_map` — where each area of the volume begins, and how big it is.
//!
//! The one report that answers "what is this volume shaped like" without a
//! dump tool. Every figure comes off the superblock the mount already read.

use alloc::format;
use alloc::string::String;
use alloc::sync::Arc;

use crate::fsattr::Attr;
use crate::mount::F2fs;
use crate::sb::SuperBlock;
use crate::uapi::BLKSIZE;

/// The report. `sit`, `nat` and `ssa` addresses come from the superblock
/// rather than from each subsystem's own cached base: they are the same
/// numbers, and reading them from one place is what makes the report a
/// description of the volume instead of of the mount.
/// # C: O(devices)
pub fn disk_map_body(sb: &SuperBlock) -> String {
    let per_seg = u64::from(sb.blks_per_seg());
    let blk = BLKSIZE as u64;
    let mut s = format!("Address Layout   : {:5}B Block address (# of Segments)\n", blk);
    s.push_str(&format!(" SB            : {:>12}\n", "0/1024B"));
    s.push_str(&format!(" seg0_blkaddr  : 0x{:010x}\n", sb.segment0_blkaddr));
    s.push_str(&format!(" Checkpoint    : 0x{:010x} ({:10})\n", sb.cp_blkaddr, 2));
    s.push_str(&format!(" SIT           : 0x{:010x} ({:10})\n",
        sb.sit_blkaddr, sb.segment_count_sit));
    s.push_str(&format!(" NAT           : 0x{:010x} ({:10})\n",
        sb.nat_blkaddr, sb.segment_count_nat));
    s.push_str(&format!(" SSA           : 0x{:010x} ({:10})\n",
        sb.ssa_blkaddr, sb.segment_count_ssa));
    s.push_str(&format!(" Main          : 0x{:010x} ({:10})\n",
        sb.main_blkaddr, sb.segment_count_main));
    s.push_str(&format!(" Block size    : {:12} KB\n", blk >> 10));
    s.push_str(&format!(" Segment size  : {:12} MB\n", (per_seg * blk) >> 20));
    s.push_str(&format!(" Segs/Sections : {:12}\n", sb.segs_per_sec));
    s.push_str(&format!(" Section size  : {:12} MB\n",
        (u64::from(sb.segs_per_sec) * per_seg * blk) >> 20));
    s.push_str(&format!(" # of Sections : {:12}\n", sb.section_count));

    if !sb.multi_device() { return s; }

    // A multi-device volume names each member's segment span. This build
    // refuses such a volume at mount, so the section is unreachable today and
    // is here because the field it renders is on the medium either way.
    s.push_str("\nDisk Map for multi devices:\n");
    let mut start = 0u32;
    for (i, segs) in sb.device_segments.iter().enumerate() {
        let end = start.saturating_add(segs.saturating_mul(sb.blks_per_seg()));
        s.push_str(&format!("Disk:{:2}: 0x{:010x} - 0x{:010x}\n", i, start, end.saturating_sub(1)));
        start = end;
    }
    s
}

/// # C: O(devices)
pub(crate) fn file(fs: &Arc<F2fs>, dev: &str) -> Attr {
    let fs = Arc::clone(fs);
    Attr::ro(dev, "disk_map", Arc::new(move || {
        Ok(disk_map_body(fs.volume.lock().super_block()).into_bytes())
    }))
}
