use vfs::Inode;

use super::data::Ext4FileData;

/// Translate one initialized filesystem page into the device's persistent
/// memory aperture. Holes and unwritten extents stay on the normal fault path.
/// # C: O(PAGE_SIZE / block_size + extents)
pub(crate) fn mmap_frame(inode: &Inode, off: u64) -> Option<u64> {
    if inode.i_flags() & vfs::inode::S_DAX == 0 { return None; }
    let d = inode.private::<Ext4FileData>()?;
    let region = d.st.mount.dax_region()?;
    let bs = u64::from(d.st.mount.sb.block_size);
    if bs == 0 || hal::PAGE_SIZE_BYTES % bs != 0 || off % hal::PAGE_SIZE_BYTES != 0 { return None; }
    let first = off / bs;
    let count = hal::PAGE_SIZE_BYTES / bs;
    let runs = d.st.mount.extent_map(d.ino).ok()?;
    let mut first_phys = None;
    for i in 0..count {
        let logical = first + i;
        let (run_logical, run_physical, run_len, unwritten) = *runs.iter()
            .find(|&&(l, _, len, _)| logical >= u64::from(l)
                && logical < u64::from(l) + u64::from(len))?;
        if unwritten { return None; }
        let pa = run_physical.checked_add(logical - u64::from(run_logical))?;
        if i == 0 { first_phys = Some(pa); }
        else if pa != first_phys? + i { return None; }
        let _ = run_len;
    }
    let byte = first_phys?.checked_mul(bs)?.checked_add(region.partition_offset)?;
    region.physical_address(byte, hal::PAGE_SIZE_BYTES)
}
