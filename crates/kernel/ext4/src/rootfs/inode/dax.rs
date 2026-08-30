use vfs::Inode;

use super::data::Ext4FileData;

use crate::rootfs::inode::regular::fs_err;

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

/// Prepare a DAX shared-write fault: allocate holes, zero their persistent
/// blocks, and convert unwritten extents before the VMM installs a PTE.
/// # C: O(PAGE_SIZE / block_size × extent walk + journal I/O)
pub(crate) fn page_mkwrite(inode: &Inode, off: u64) -> vfs::KResult<()> {
    let d = inode.private::<Ext4FileData>().ok_or(vfs::VfsError::Eio)?;
    let _mutation = d.begin_swap_mutation(inode)?;
    let _inode_lock = inode.inode_lock();
    // SAFETY: the DAX fault runs in process context and no spinlock is held;
    // exclusive invalidation serializes extent changes against mmap/readers.
    let _invalidate = unsafe { d.invalidate_lock.write() };
    let size = inode.size();
    if off >= size { return Err(vfs::VfsError::Eio); }
    let bs = u64::from(d.st.mount.sb.block_size);
    if bs == 0 || hal::PAGE_SIZE_BYTES % bs != 0 { return Err(vfs::VfsError::Eio); }
    let first = off / bs;
    let end = core::cmp::min(size, off.saturating_add(hal::PAGE_SIZE_BYTES));
    let last = (end.saturating_add(bs - 1) / bs).saturating_sub(1);
    for logical in first..=last {
        let mut raw = d.st.mount.read_inode(d.ino).map_err(|_| vfs::VfsError::Eio)?;
        let runs = d.st.mount.collect_inode_phys_extents(&raw).map_err(|_| vfs::VfsError::Eio)?;
        let hit = runs.iter().find(|r| logical >= u64::from(r.logical)
            && logical < u64::from(r.logical) + u64::from(r.len));
        if hit.is_none() {
            d.st.mount.fallocate_inode(d.ino, logical * bs, bs, true)
                .map_err(|e| fs_err(&d.st, e))?;
            raw = d.st.mount.read_inode(d.ino).map_err(|_| vfs::VfsError::Eio)?;
        }
        d.st.mount.convert_unwritten_at_cached(d.ino, logical as u32, &raw)
            .map_err(|e| fs_err(&d.st, e))?;
    }
    d.refresh_inode_usage(inode);
    Ok(())
}
