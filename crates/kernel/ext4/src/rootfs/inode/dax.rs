use vfs::Inode;

use super::data::Ext4FileData;

#[cfg(target_os = "oxide-kernel")]
fn physical_at(d: &Ext4FileData, off: u64) -> Option<u64> {
    let bs = u64::from(d.st.mount.sb.block_size);
    let logical = off / bs;
    let (start, phys, _len, unwritten) = *d.st.mount.extent_map(d.ino).ok()?.iter()
        .find(|&&(l, _, n, _)| logical >= u64::from(l)
            && logical < u64::from(l) + u64::from(n))?;
    if unwritten { return None; }
    let byte = phys.checked_add(logical - u64::from(start))?.checked_mul(bs)?
        .checked_add(off % bs)?.checked_add(d.st.mount.dax_region()?.partition_offset)?;
    d.st.mount.dax_region()?.physical_address(byte, 1)
}

#[cfg(target_os = "oxide-kernel")]
fn copy_from_pmem(pa: u64, dst: &mut [u8]) {
    let src = (pmm::user_as::hhdm_offset() + pa) as *const u8;
    // SAFETY: the DAX provider bounds-checked pa, HHDM covers the persistent
    // aperture, and dst is a live non-overlapping caller buffer.
    unsafe { core::ptr::copy_nonoverlapping(src, dst.as_mut_ptr(), dst.len()); }
}

#[cfg(target_os = "oxide-kernel")]
fn copy_to_pmem(src: &[u8], pa: u64) {
    let dst = (pmm::user_as::hhdm_offset() + pa) as *mut u8;
    // SAFETY: the DAX provider bounds-checked pa, HHDM covers the persistent
    // aperture, and src is a live non-overlapping caller buffer.
    unsafe { core::ptr::copy_nonoverlapping(src.as_ptr(), dst, src.len()); }
}

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
    prepare_page_locked(d, inode, off)?;
    d.refresh_inode_usage(inode);
    Ok(())
}

#[cfg(target_os = "oxide-kernel")]
pub(crate) fn read(inode: &Inode, off: u64, buf: &mut [u8]) -> vfs::KResult<usize> {
    let d = inode.private::<Ext4FileData>().ok_or(vfs::VfsError::Eio)?;
    let _inode_lock = inode.inode_lock_shared();
    // SAFETY: process-context DAX reads share the invalidate owner, so extent
    // translations remain stable for each copied range.
    let _invalidate = unsafe { d.invalidate_lock.read() };
    let size = inode.size();
    if off >= size { return Ok(0); }
    let count = core::cmp::min(buf.len(), (size - off) as usize);
    let mut done = 0usize;
    while done < count {
        let pos = off + done as u64;
        let page_left = hal::PAGE_SIZE_BYTES - (pos & (hal::PAGE_SIZE_BYTES - 1));
        let block_left = u64::from(d.st.mount.sb.block_size) - (pos % u64::from(d.st.mount.sb.block_size));
        let chunk = core::cmp::min(count - done, core::cmp::min(page_left, block_left) as usize);
        if let Some(pa) = physical_at(d, pos) { copy_from_pmem(pa, &mut buf[done..done + chunk]); }
        else { buf[done..done + chunk].fill(0); }
        done += chunk;
    }
    Ok(done)
}

#[cfg(not(target_os = "oxide-kernel"))]
pub(crate) fn read(_inode: &Inode, _off: u64, _buf: &mut [u8]) -> vfs::KResult<usize> {
    Err(vfs::VfsError::Eio)
}

#[cfg(target_os = "oxide-kernel")]
pub(crate) fn write(inode: &Inode, off: u64, buf: &[u8]) -> vfs::KResult<usize> {
    let d = inode.private::<Ext4FileData>().ok_or(vfs::VfsError::Eio)?;
    if buf.is_empty() { return Ok(0); }
    let end = off.checked_add(buf.len() as u64).ok_or(vfs::VfsError::Einval)?;
    let _mutation = d.begin_swap_mutation(inode)?;
    let _inode_lock = inode.inode_lock();
    // SAFETY: process-context DAX writes exclusively hold extent invalidation
    // while allocation, conversion, and persistent CPU stores are performed.
    let _invalidate = unsafe { d.invalidate_lock.write() };
    let extending = end > inode.size();
    if extending {
        // Linux ext4_dax_write_iter puts an extending write on the orphan
        // list before allocation.  Recovery can then truncate blocks and
        // restore the inode if power is lost between allocation and the final
        // inode-size update.
        d.st.mount.orphan_add(d.ino)
            .map_err(|e| crate::rootfs::fserror::report(&d.st, e))?;
        d.st.mount.fallocate_inode(d.ino, off, end - off, false)
            .map_err(|e| crate::rootfs::fserror::report(&d.st, e))?;
        d.refresh_inode_usage(inode);
        // `ext4_fallocate` with KEEP_SIZE clear allocates the blocks but the
        // extent owner does not publish i_size until the data is persistent.
        // The DAX fault preparation still needs the new logical EOF to admit
        // the page, so publish the in-core size at the same boundary Linux's
        // iomap actor uses for an extending write.
        super::data::publish_size_max(inode, end);
    }
    let mut done = 0usize;
    while done < buf.len() {
        let pos = off + done as u64;
        let page_end = (pos / hal::PAGE_SIZE_BYTES + 1) * hal::PAGE_SIZE_BYTES;
        let block_left = u64::from(d.st.mount.sb.block_size) - (pos % u64::from(d.st.mount.sb.block_size));
        let chunk = core::cmp::min(buf.len() - done, core::cmp::min(page_end - pos, block_left) as usize);
        prepare_page_locked(d, inode, pos & !(hal::PAGE_SIZE_BYTES - 1))?;
        let pa = physical_at(d, pos).ok_or(vfs::VfsError::Eio)?;
        copy_to_pmem(&buf[done..done + chunk], pa);
        done += chunk;
    }
    if extending {
        d.st.mount.set_inode_size(d.ino, end)
            .map_err(|e| crate::rootfs::fserror::report(&d.st, e))?;
        d.st.mount.orphan_del(d.ino)
            .map_err(|e| crate::rootfs::fserror::report(&d.st, e))?;
    }
    Ok(done)
}

#[cfg(not(target_os = "oxide-kernel"))]
pub(crate) fn write(_inode: &Inode, _off: u64, _buf: &[u8]) -> vfs::KResult<usize> {
    Err(vfs::VfsError::Eio)
}

#[cfg(target_os = "oxide-kernel")]
fn prepare_page_locked(d: &Ext4FileData, inode: &Inode, off: u64) -> vfs::KResult<()> {
    let size = inode.size();
    if off >= size { return Err(vfs::VfsError::Eio); }
    let bs = u64::from(d.st.mount.sb.block_size);
    if bs == 0 || hal::PAGE_SIZE_BYTES % bs != 0 { return Err(vfs::VfsError::Eio); }
    let first = off / bs;
    let end = core::cmp::min(size, off.saturating_add(hal::PAGE_SIZE_BYTES));
    let last = (end.saturating_add(bs - 1) / bs).saturating_sub(1);
    for logical in first..=last {
        let raw = d.st.mount.read_inode(d.ino).map_err(|_| vfs::VfsError::Eio)?;
        let runs = d.st.mount.collect_inode_phys_extents(&raw).map_err(|_| vfs::VfsError::Eio)?;
        if !runs.iter().any(|r| logical >= u64::from(r.logical)
            && logical < u64::from(r.logical) + u64::from(r.len)) {
            d.st.mount.fallocate_inode(d.ino, logical * bs, bs, true)
                .map_err(|e| crate::rootfs::fserror::report(&d.st, e))?;
        }
        let raw = d.st.mount.read_inode(d.ino).map_err(|_| vfs::VfsError::Eio)?;
        d.st.mount.convert_unwritten_at_cached(d.ino, logical as u32, &raw)
            .map_err(|e| crate::rootfs::fserror::report(&d.st, e))?;
    }
    Ok(())
}

#[cfg(not(target_os = "oxide-kernel"))]
fn prepare_page_locked(_d: &Ext4FileData, _inode: &Inode, _off: u64) -> vfs::KResult<()> {
    Err(vfs::VfsError::Eio)
}
