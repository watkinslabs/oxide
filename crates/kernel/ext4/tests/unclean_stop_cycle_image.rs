//! Does a journalled root image plus an orderly stop actually stop the boot
//! filesystem rotting, or was that only a plausible story?
//!
//! The boot harness ended every run by killing QEMU, and the image was made
//! with `mkfs.ext4 -O ^has_journal`, so nothing replayed on the next mount and
//! each run inherited the previous run's torn metadata. Either half alone is
//! useless: a journal whose guest is always killed replays on every boot, and
//! an orderly shutdown without a journal still loses whatever was in flight.
//!
//! Measured rather than asserted. `PowerCutDisk` stops the machine between two
//! arbitrary block writes — the kill model, not a JBD2 boundary — the image is
//! remounted exactly as the next boot would remount it, and stock `e2fsck -fn`
//! gives the verdict. Both variants are made here with the image builder's own
//! mkfs options, so the journal flag is the only thing that differs, and both
//! go through the same mount lifecycle stamps the real root mount performs.
//!
//! Skips when e2fsprogs is not on PATH: the verdict is a stock fsck's, and
//! there is nothing to say without one.

extern crate alloc;
mod common;

use alloc::sync::Arc;
use block::BlockDevice;
use common::powercut::PowerCutDisk;

const SECTOR: u32 = 512;
/// Image bytes: enough that mkfs gives the journalled variant a real log, small
/// enough to keep every cycle inside the hosted frame pool.
const IMAGE_BYTES: u64 = 32 * 1024 * 1024;
/// Inode count, sized the way the image builder sizes it: from the file count.
const INODES: u32 = 2048;
/// Cut points swept per variant, and their stride. One cut point proves nothing
/// about a harness that stops the guest wherever it happens to be.
const MAX_CUT: u64 = 160;
const CUT_STRIDE: usize = 3;
/// Unclean stops chained onto one image — the "across boots" in the defect.
const CYCLES: u32 = 8;

fn temp_path(tag: &str) -> std::path::PathBuf {
    use std::sync::atomic::{AtomicU32, Ordering};
    static SEQ: AtomicU32 = AtomicU32::new(0);
    let mut path = std::env::temp_dir();
    path.push(std::format!("oxide-unclean-{}-{}-{}.img", tag,
        std::process::id(), SEQ.fetch_add(1, Ordering::Relaxed)));
    path
}

/// Build an image with the image builder's mkfs options; `features` is the only
/// thing that varies. None when mke2fs is unavailable.
fn mkfs(features: &str) -> Option<std::vec::Vec<u8>> {
    let path = temp_path("mkfs");
    std::fs::File::create(&path).ok()?.set_len(IMAGE_BYTES).ok()?;
    let out = std::process::Command::new("mkfs.ext4")
        .args(["-q", "-F", "-O", features, "-L", "oxide", "-N", &std::format!("{INODES}")])
        .arg(&path).output();
    let bytes = match out {
        Ok(o) if o.status.success() => std::fs::read(&path).ok(),
        Ok(o) => { eprintln!("mkfs.ext4 {features}: {}", String::from_utf8_lossy(&o.stderr)); None }
        Err(_) => None,
    };
    let _ = std::fs::remove_file(&path);
    bytes
}

/// `e2fsck -fn` verdict. Some(true) = clean, Some(false) = damage an unattended
/// fsck would have to repair, None = e2fsck unavailable.
fn e2fsck_clean(bytes: &[u8], label: &str) -> Option<bool> {
    let path = temp_path("fsck");
    std::fs::write(&path, bytes).ok()?;
    let out = std::process::Command::new("e2fsck").arg("-fn").arg(&path).output();
    let _ = std::fs::remove_file(&path);
    match out {
        Ok(o) => {
            if !o.status.success() {
                eprintln!("--- e2fsck -fn {label} ---\n{}", String::from_utf8_lossy(&o.stdout));
            }
            Some(o.status.success())
        }
        Err(_) => None,
    }
}

/// Metadata-heavy work: allocation bitmaps, inode table, directory blocks and
/// extent trees all change, so an interrupted run has something to tear.
///
/// Every operation here is complete on its own. `dir_unlink` is deliberately
/// absent: it removes the directory entry and leaves the link count to its
/// caller, so a workload that called it would hand e2fsck unattached inodes it
/// was right to complain about, and the measurement would blame the power cut.
fn workload(m: &ext4::Mount, tag: u32) {
    let bs = m.sb.block_size as usize;
    let Ok(dir) = m.create_dir(2, std::format!("d{tag}").as_bytes(), 0o755, 0, 0) else { return };
    for i in 0..12u32 {
        let Ok(f) = m.create_file(dir, std::format!("f{i}.bin").as_bytes(), 0o644, 0, 0) else { continue };
        let payload: std::vec::Vec<u8> = (0..(bs * 2 + 97)).map(|b| (b & 0xFF) as u8).collect();
        let _ = m.write_at(f, (bs / 2) as u64, &payload);
    }
}

/// Mount, stamp the superblock the way the root mount does, run `workload`,
/// then lose power after `cut_after` further writes. Returns the bytes that
/// reached the media, and whether power was actually cut.
fn run_until_power_cut(image: &[u8], cut_after: u64, tag: u32) -> (std::vec::Vec<u8>, bool) {
    let disk = PowerCutDisk::new(image, SECTOR);
    {
        let dev: Arc<dyn BlockDevice> = disk.clone();
        let Ok(m) = ext4::Mount::open(dev) else { return (disk.snapshot(), false) };
        // A rw mount clears EXT4_VALID_FS and, with a journal, advertises
        // INCOMPAT_RECOVER for the whole mounted window. Skipping this is what
        // makes a journal look useless: the log holds the transaction and
        // nothing on the next mount is told to read it.
        if m.mark_state_dirty().is_err() { return (disk.snapshot(), false); }
        disk.cut_after(cut_after);
        workload(&m, tag);
    }
    (disk.snapshot(), disk.crashed())
}

/// The next boot: remount (replaying the journal when there is one) and stop
/// cleanly. Returns the bytes an `e2fsck` would then see.
fn remount_and_stop_cleanly(image: &[u8]) -> std::vec::Vec<u8> {
    let disk = PowerCutDisk::new(image, SECTOR);
    let dev: Arc<dyn BlockDevice> = disk.clone();
    match ext4::Mount::open(dev) {
        Ok(m) => { let _ = m.mark_state_dirty(); let _ = m.mark_state_clean(); }
        Err(e) => eprintln!("remount after the power cut failed: {e:?}"),
    }
    disk.snapshot()
}

/// Damaged/total over every cut point that actually lost power.
fn sweep_cut_points(image: &[u8], label: &str) -> (u32, u32) {
    let (mut dirty, mut total) = (0u32, 0u32);
    for point in (1..=MAX_CUT).step_by(CUT_STRIDE) {
        let (cut, crashed) = run_until_power_cut(image, point, point as u32);
        if !crashed { continue; }
        total += 1;
        let next = remount_and_stop_cleanly(&cut);
        match e2fsck_clean(&next, &std::format!("{label} cut@{point}")) {
            Some(false) => { dirty += 1; eprintln!("  {label} cut@{point}: DAMAGED"); }
            Some(true) | None => {}
        }
    }
    eprintln!("unclean-stop sweep [{label}]: {dirty}/{total} cut points left permanent damage");
    (dirty, total)
}

fn skip_without_e2fsprogs() -> Option<(std::vec::Vec<u8>, std::vec::Vec<u8>)> {
    let nojournal = mkfs("^has_journal")?;
    let journal = mkfs("has_journal")?;
    e2fsck_clean(&nojournal, "fresh")?;
    assert_eq!(e2fsck_clean(&nojournal, "fresh ^has_journal"), Some(true),
        "a freshly made image must be clean, or nothing measured against it means anything");
    assert_eq!(e2fsck_clean(&journal, "fresh has_journal"), Some(true),
        "a freshly made image must be clean, or nothing measured against it means anything");
    Some((nojournal, journal))
}

/// The pair, measured against each other at the same power-cut points.
#[test]
fn a_journal_survives_the_unclean_stops_that_damage_a_journalless_image() {
    common::boot_hosted_pmm();
    let Some((nojournal, journal)) = skip_without_e2fsprogs() else {
        eprintln!("e2fsprogs unavailable — skipping the unclean-stop measurement");
        return;
    };
    let (without, cuts_without) = sweep_cut_points(&nojournal, "^has_journal");
    let (with, cuts_with) = sweep_cut_points(&journal, "has_journal");

    assert!(cuts_without > 0 && cuts_with > 0,
        "no cut point actually lost power ({cuts_without}, {cuts_with}); the measurement is empty");
    // The positive control: without a journal an unclean stop MUST be able to
    // damage the image, or this test could not have failed before the fix.
    assert!(without > 0,
        "no unclean stop damaged the journalless image in {cuts_without} cut points; \
         this measurement cannot detect the defect it exists for");
    assert_eq!(with, 0,
        "with a journal, {with}/{cuts_with} unclean stops still left permanent damage \
         (without a journal: {without}/{cuts_without})");
}

/// Damage accumulates across boots, which is the defect's actual shape: each
/// cycle inherits the previous cycle's bytes.
#[test]
fn a_journalled_image_stays_clean_across_chained_unclean_stops() {
    common::boot_hosted_pmm();
    let Some((_, journal)) = skip_without_e2fsprogs() else {
        eprintln!("e2fsprogs unavailable — skipping the chained unclean-stop measurement");
        return;
    };
    let mut bytes = journal;
    let mut cuts = 0u32;
    for cycle in 0..CYCLES {
        // Vary the cut across cycles: one boundary repeated is one measurement.
        let (cut, crashed) = run_until_power_cut(&bytes, 7 + u64::from(cycle) * 11, cycle);
        if crashed { cuts += 1; }
        bytes = remount_and_stop_cleanly(&cut);
        assert_eq!(e2fsck_clean(&bytes, &std::format!("journalled cycle {cycle}")), Some(true),
            "cycle {cycle} of {CYCLES} left damage the next boot inherits");
    }
    assert!(cuts == CYCLES, "only {cuts}/{CYCLES} cycles actually lost power");
    eprintln!("chained unclean stops [has_journal]: {CYCLES} cycles, {cuts} power cuts, still clean");
}

/// The other half of the pair: an orderly stop leaves a clean image, with or
/// without a journal. Without this, "we killed it" and "it shut down" would
/// look the same to the measurement above.
#[test]
fn an_orderly_stop_leaves_a_clean_image() {
    common::boot_hosted_pmm();
    let Some((nojournal, journal)) = skip_without_e2fsprogs() else {
        eprintln!("e2fsprogs unavailable — skipping the orderly-stop measurement");
        return;
    };
    for (label, image) in [("^has_journal", nojournal), ("has_journal", journal)] {
        let disk = PowerCutDisk::new(&image, SECTOR);
        {
            let dev: Arc<dyn BlockDevice> = disk.clone();
            let m = ext4::Mount::open(dev).expect("mount");
            m.mark_state_dirty().expect("rw mount stamp");
            disk.watch();
            workload(&m, 0);
            m.mark_state_clean().expect("clean unmount stamp");
        }
        assert!(!disk.crashed(), "{label}: an orderly stop must not lose a write");
        assert_eq!(e2fsck_clean(&disk.snapshot(), &std::format!("{label} orderly stop")), Some(true),
            "{label}: an orderly stop left a damaged image");
    }
}
