//! `/sys/fs/f2fs/<dev>/` — what one mount is doing right now.

use alloc::format;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;

use syscall::errno::Errno;

use crate::casefold::LookupMode;
use crate::fsattr::{line_hex, line_u64, Attr, ShowFn};
use crate::mount::{errno_to_vfs, F2fs};
use crate::volume::Volume;

/// The volume a mount's attribute reads through.
pub(crate) type Vol = Volume<crate::mount::devs::Medium>;

/// A read-only attribute rendering one number off the live volume.
/// # C: O(1)
pub(crate) fn num(fs: &Arc<F2fs>, dir: &str, name: &'static str,
                  f: fn(&mut Vol) -> Result<u64, Errno>) -> Attr {
    Attr::ro(dir, name, render(fs, f, line_u64))
}

/// A read-only attribute rendering one number in hexadecimal, which is how a
/// flag word is reported. # C: O(1)
pub(crate) fn hex(fs: &Arc<F2fs>, dir: &str, name: &'static str,
                  f: fn(&mut Vol) -> Result<u64, Errno>) -> Attr {
    Attr::ro(dir, name, render(fs, f, line_hex))
}

/// A control over one number the VOLUME owns, as against one the background
/// threads own.
///
/// Both halves take the volume lock and release it before anything leaves, so
/// a refused value is refused before the lock is dropped and cannot be
/// overtaken by the read that follows it.
/// # C: O(1)
pub(crate) fn num_rw(fs: &Arc<F2fs>, dir: &str, name: &'static str,
                     get: fn(&Vol) -> u64, set: fn(&mut Vol, u64) -> Result<(), Errno>) -> Attr {
    let show_fs = Arc::clone(fs);
    let store_fs = Arc::clone(fs);
    Attr::rw(
        dir,
        name,
        Arc::new(move || Ok(line_u64(get(&show_fs.volume.lock())))),
        Arc::new(move |bytes: &[u8]| {
            let v = crate::bg::knobs::parse_value(bytes).map_err(errno_to_vfs)?;
            set(&mut store_fs.volume.lock(), v).map_err(errno_to_vfs)?;
            Ok(bytes.len())
        }),
    )
}

/// A read-only attribute whose value is text rather than a number.
/// # C: O(len)
pub(crate) fn text(fs: &Arc<F2fs>, dir: &str, name: &'static str,
                   f: fn(&mut Vol) -> Result<String, Errno>) -> Attr {
    Attr::ro(dir, name, render(fs, f, |s: String| s.into_bytes()))
}

/// Bind a reader to the mount and to a formatter. The lock is taken for the
/// read and released before the bytes leave, so an attribute read never holds
/// it across the copy out. # C: O(f)
fn render<T: 'static>(fs: &Arc<F2fs>, f: fn(&mut Vol) -> Result<T, Errno>,
                      fmt: fn(T) -> Vec<u8>) -> ShowFn {
    let fs = Arc::clone(fs);
    Arc::new(move || {
        let value = { let mut v = fs.volume.lock(); f(&mut v).map_err(errno_to_vfs)? };
        Ok(fmt(value))
    })
}

/// Every attribute directly under one mount's directory. # C: O(1)
pub(crate) fn attrs(fs: &Arc<F2fs>, dev: &str) -> Vec<Attr> {
    alloc::vec![
        num(fs, dev, "main_blkaddr", |v| Ok(u64::from(v.super_block().main_blkaddr))),
        num(fs, dev, "dirty_segments", dirty_segments),
        num(fs, dev, "free_segments", free_segments),
        num(fs, dev, "ovp_segments", |v| Ok(u64::from(v.checkpoint().overprov_segment_count))),
        num_rw(fs, dev, "reserved_segments", |v| u64::from(v.gc_reserve()),
               set_reserved_segments),
        num(fs, dev, "unusable", unusable),
        num(fs, dev, "current_reserved_blocks", |v| Ok(v.current_reserved_blocks())),
        num(fs, dev, "mounted_time_sec", |v| Ok(v.checkpoint().elapsed_time)),
        num(fs, dev, "pending_discard", pending_discard),
        num(fs, dev, "lifetime_write_kbytes", |v| Ok(v.lifetime_write_kbytes())),
        // What the mount SETTLED ON, not what it asked for. A volume too young
        // for age-threshold cleaning mounts with the option and the policy
        // off, and reporting the option here would tell a tool the policy was
        // running when no candidate can ever clear its threshold.
        num(fs, dev, "atgc_enabled", |v| Ok(u64::from(v.atgc_enabled()))),
        hex(fs, dev, "encoding_flags", |v| Ok(u64::from(v.super_block().s_encoding_flags))),
        text(fs, dev, "encoding", encoding),
        text(fs, dev, "effective_lookup_mode", effective_lookup_mode),
        text(fs, dev, "features", features),
        extension_list_attr(fs, dev),
    ]
}

/// Change the live allocator reserve; the checkpoint remains the on-disk
/// format value, as it does for Linux's runtime control. # C: O(1)
fn set_reserved_segments(v: &mut Vol, n: u64) -> Result<(), Errno> {
    v.set_reserved_segments(n)
}

/// Blocks stranded in partial dirty segments after overprovision holes are
/// removed. Data and node holes are tracked separately, and the larger one is
/// the unusable amount Linux exposes. # C: O(main segments)
fn unusable(v: &mut Vol) -> Result<u64, Errno> {
    v.load_segments()?;
    let mut holes = [0u64; 2];
    for segno in 0..v.super_block().segment_count_main {
        if v.is_current(segno) { continue; }
        let e = &v.segments()[segno as usize];
        let valid = u64::from(e.valid_blocks());
        let usable = u64::from(crate::zoned::usable::usable_blks_in_seg(
            v.super_block(), v.zones(), segno));
        if valid == 0 || valid >= usable { continue; }
        let kind = usize::from(e.seg_type() >= crate::uapi::NR_CURSEG_DATA_TYPE as u8);
        holes[kind] = holes[kind].saturating_add(usable - valid);
    }
    let overprov = v.checkpoint().overprov_segment_count
        .saturating_sub(v.gc_reserve());
    let overprov_holes = u64::from(overprov)
        .saturating_mul(u64::from(v.super_block().blks_per_seg()));
    Ok(holes[0].max(holes[1]).saturating_sub(overprov_holes))
}

/// The two extension lists, and the one write that changes them.
///
/// Writable because the change reaches the MEDIUM: the lists live in the
/// superblock, so a name added here is seen by every later mount, which is what
/// a tool writing it is asking for. A write that the medium refuses is undone
/// by the volume before it returns, so what this file reports is always what the
/// medium holds.
/// # C: O(N extensions) to read; one block per superblock copy to write
fn extension_list_attr(fs: &Arc<F2fs>, dir: &str) -> Attr {
    let show_fs = Arc::clone(fs);
    let store_fs = Arc::clone(fs);
    Attr::rw(
        dir,
        "extension_list",
        Arc::new(move || {
            let text = { let mut v = show_fs.volume.lock();
                         extension_list(&mut v).map_err(errno_to_vfs)? };
            Ok(text.into_bytes())
        }),
        Arc::new(move |bytes: &[u8]| {
            let line = core::str::from_utf8(bytes).map_err(|_| errno_to_vfs(Errno::Einval))?;
            let c = crate::place::extlist::parse(line).map_err(errno_to_vfs)?;
            store_fs.volume.lock().update_extension_list(c.name, c.hot, c.set)
                .map_err(errno_to_vfs)?;
            Ok(bytes.len())
        }),
    )
}

/// Segments in use, not full, and not the one a log is filling.
///
/// A segment with no live block is not dirty — it is free, or waiting for the
/// checkpoint that frees it — and a full one has nothing left to reclaim, so
/// neither is what a cleaner is looking at. The table is read in whole first
/// because a mount that has not written yet has never had reason to load it,
/// and reporting zero would say the volume is pristine.
/// # C: O(main segments), plus the table read on the first call
pub(crate) fn dirty_segments(v: &mut Vol) -> Result<u64, Errno> {
    v.load_segments()?;
    let per = v.super_block().blks_per_seg() as u16;
    let n = v.super_block().segment_count_main;
    Ok((0..n).filter(|&s| {
        let live = v.seg_valid(s);
        live > 0 && live < per && !v.is_current(s)
    }).count() as u64)
}

/// # C: O(main segments), plus the table read on the first call
fn free_segments(v: &mut Vol) -> Result<u64, Errno> {
    v.load_segments()?;
    Ok(u64::from(v.free_segment_count()))
}

/// Discard requests waiting to be announced — RUNS, not blocks, because a
/// request covers a run. The block count is `stat/undiscard_blks`, and both come
/// off the discard control, which is the one thing that knows what is still
/// outstanding.
/// # C: O(MAX_PLIST_NUM)
fn pending_discard(v: &mut Vol) -> Result<u64, Errno> { Ok(v.discard_runs_waiting()) }

/// The Unicode version names resolve through, or that none does. # C: O(1)
fn encoding(v: &mut Vol) -> Result<String, Errno> {
    match v.casefold() {
        Some(c) => {
            let i = c.info();
            Ok(format!("UTF-8 ({}.{}.{})\n", i.major, i.minor, i.revision))
        }
        None => Ok(String::from("(none)\n")),
    }
}

/// Which of the two lookup passes a case-folding mount will actually make.
///
/// `auto` is not an answer on its own: it resolves to the fast path or the
/// compatible one according to whether the volume was formatted saying its
/// entries never need the slow rescan.
/// # C: O(1)
fn effective_lookup_mode(v: &mut Vol) -> Result<String, Errno> {
    let mode = v.options().lookup_mode;
    let no_fallback = v.super_block().s_encoding_flags
        & crate::casefold::ENC_NO_COMPAT_FALLBACK_FL != 0;
    Ok(line_text(match mode {
        LookupMode::Perf => "perf",
        LookupMode::Compat => "compat",
        LookupMode::Auto if no_fallback => "auto:perf",
        LookupMode::Auto => "auto:compat",
    }))
}

/// # C: O(len)
fn line_text(s: &str) -> String { let mut o = String::from(s); o.push('\n'); o }

/// On-disk feature bits as one comma-separated line — the older form of
/// `feature_list/`, kept because tools still read it. # C: O(N bits)
fn features(v: &mut Vol) -> Result<String, Errno> {
    let f = v.super_block().feature;
    let mut out = String::new();
    for (bit, name) in super::feature_list::BITS {
        if f & bit == 0 { continue; }
        if !out.is_empty() { out.push_str(", "); }
        out.push_str(name);
    }
    out.push('\n');
    Ok(out)
}

/// The two extension lists the superblock carries: names whose files are
/// placed as cold data, then names whose files are placed as hot.
/// # C: O(N extensions)
fn extension_list(v: &mut Vol) -> Result<String, Errno> {
    let sb = v.super_block();
    let cold = sb.extension_count as usize;
    let hot = sb.hot_ext_count as usize;
    let mut out = String::from("cold file extension:\n");
    for e in sb.extensions.iter().take(cold) { out.push_str(e); out.push('\n'); }
    out.push_str("hot file extension:\n");
    for e in sb.extensions.iter().skip(cold).take(hot) { out.push_str(e); out.push('\n'); }
    Ok(out)
}
