// `IORING_REGISTER_ZCRX_IFQ` and `IORING_REGISTER_ZCRX_CTRL`.
//
// Registration builds three things in a fixed order, and the order is what
// makes every failure recoverable: the refill-queue region first (it is the
// only piece the caller must be told where to map), then the area (pinning the
// caller's own pages), then the device binding. Nothing is published under an
// id until all three exist AND the caller has been told the geometry — a
// caller that could not be told cannot use the queue, so an unreportable
// registration is torn down rather than left half-live.

use alloc::sync::Arc;

use syscall::errno::Errno;

use crate::io_uring::ctx::IoUringInode;
use crate::io_uring::pin::PinnedRange;
use crate::io_uring::region::Region;
use crate::io_uring::zcrx::area::ZcrxArea;
use crate::io_uring::zcrx::ifq::{provider_of, Binding, ZcrxIfq};
use crate::io_uring::zcrx::rq::ZcrxRq;
use crate::io_uring_abi::acct::{Ledgers, RingAcct};
use crate::io_uring_abi::mem_region::{admit_region_desc, RegionDesc, REGION_DESC_BYTES};
use crate::io_uring_abi::zcrx::*;

use net::page_pool::MpParams;

fn err(e: Errno) -> i64 { -(e.as_i32() as i64) }

/// Read the caller's region descriptor. # C: O(1)
fn read_region_desc(ptr: u64) -> Result<RegionDesc, Errno> {
    let mut b = [0u8; REGION_DESC_BYTES as usize];
    if uaccess::copy_from_user(&mut b, ptr).is_err() { return Err(Errno::Efault); }
    Ok(RegionDesc::from_bytes(&b))
}

/// Build the refill-queue region and the queue over it. # C: O(N_pages)
fn build_rq(reg: &IfqReg, rd: &mut RegionDesc, notif: &NotifDesc, id: u32, acct: RingAcct)
    -> Result<ZcrxRq, Errno>
{
    admit_region_desc(rd, hal::PAGE_SIZE_BYTES)?;
    // A caller-provided region is not mappable from the ring fd, and the
    // refill queue must be: the caller writes it and the kernel reads it
    // through the same pages.
    if rd.user_provided() { return Err(Errno::Einval); }
    admit_rq_region(reg.rq_entries, rd.size)?;
    let stats_off = if notif.flags & ZCRX_NOTIF_DESC_FLAG_STATS != 0 {
        Some(admit_notif_stats(notif.stats_offset, reg.rq_entries, rd.size)?)
    } else { None };

    let bytes = u32::try_from(rd.size).map_err(|_| Errno::Enomem)?;
    let region = Region::alloc(bytes, acct).ok_or(Errno::Enomem)?;
    rd.mmap_offset = zcrx_mmap_offset(id);
    Ok(ZcrxRq::new(region, reg.rq_entries, stats_off))
}

/// Pin the caller's area and split it into buffers. # C: O(N_pages)
fn build_area(area: &mut AreaReg, buf_shift: u32, acct: RingAcct) -> Result<ZcrxArea, Errno> {
    // The receive area is the CALLER's own memory held down by the kernel for
    // transfers into it, so it books the mm's pinned total as well.
    let mem = PinnedRange::pin(area.addr, area.len, acct, Ledgers::UserAndMm)?;
    let a = ZcrxArea::new(mem, buf_shift)?;
    area.rq_area_token = (a.area_id as u64) << IORING_ZCRX_AREA_SHIFT;
    Ok(a)
}

/// Bind the named device receive queue to this instance. # C: O(1)
fn bind_device(ifq: &Arc<ZcrxIfq>, if_idx: u32, if_rxq: u32, rx_page_size: u32)
    -> Result<(), i64>
{
    let ns = net::netdev::current_net_ns();
    let Some((_id, dev, queues)) = net::sock::stack().ifaces.lookup_rx_queues_in_ns(if_idx, ns)
        else { return Err(err(Errno::Enodev)) };
    let params = MpParams { ops: provider_of(ifq), rx_page_size };
    if let Err(e) = net::netdev::rx_queue::mp_open_rxq(&dev, &queues, if_rxq, &params) {
        return Err(crate::net_errno::errno_from_neterr(e));
    }
    *ifq.binding.lock() = Some(Binding { dev, queues, rxq: if_rxq, params });
    Ok(())
}

/// Adopt an instance another ring exported — `ZCRX_REG_IMPORT`.
///
/// The adopting ring gets its OWN id for the instance and its own table slot;
/// everything the instance is made of stays where the registering ring put it.
/// Becoming a user is the first thing that happens after the descriptor
/// resolves, so an instance every ring has already let go cannot be adopted
/// back into service. # C: O(N_ifqs)
fn import(ring: &Arc<IoUringInode>, reg: &mut IfqReg, arg: u64) -> i64 {
    if let Err(e) = admit_ifq_import(reg) { return err(e); }
    let Some(cur) = sched::live::current() else { return err(Errno::Ebadf) };
    // SAFETY: running task on this CPU; preempt-off; sole reader of the fd_table slot.
    let Some(fdt) = (unsafe { cur.fd_table_ref() }) else { return err(Errno::Ebadf) };
    let file = match fdt.clone().get(reg.if_idx as i32) { Ok(f) => f, Err(_) => return err(Errno::Ebadf) };
    // A descriptor that carries no instance is not an exported one, whatever
    // else it is — the same answer a descriptor that names nothing gets.
    let Some(ifq) = crate::io_uring::zcrx::box_fd::ifq_of(&file) else { return err(Errno::Ebadf) };
    if !ifq.get_user() { return err(Errno::Ebadf); }

    let id = match ring.zcrx_claim_id() { Ok(i) => i, Err(e) => { ifq.put_user(); return err(e); } };
    reg.zcrx_id = id;
    reg.offsets = ZcrxOffsets::fill();
    if uaccess::copy_to_user(arg, &reg.to_bytes()).is_err() {
        ring.zcrx_release_id(id);
        ifq.put_user();
        return err(Errno::Efault);
    }
    ring.zcrx_publish(id, ifq);
    0
}

/// Hand out a descriptor naming this instance — `ZCRX_CTRL_EXPORT`.
///
/// The descriptor is itself a user of the instance, so the queue stays bound
/// for as long as it is open even if the ring that registered the instance
/// goes away first. The user reference is taken BEFORE the description exists
/// and is released by the description's own close path, so every failure below
/// is balanced by dropping the description rather than by unwinding by hand.
/// # C: O(1)
fn export(ifq: &Arc<ZcrxIfq>, mut c: Ctrl, arg: u64) -> i64 {
    use vfs::{File, OpenFlags};
    let Some(cur) = sched::live::current() else { return err(Errno::Ebadf) };
    // SAFETY: running task on this CPU; preempt-off; sole reader of the fd_table slot.
    let Some(fdt) = (unsafe { cur.fd_table_ref() }) else { return err(Errno::Ebadf) };
    let fdt = fdt.clone();
    if !ifq.get_user() { return err(Errno::Enxio); }

    crate::io_uring::ring::install_release_hook();
    let inode = crate::io_uring::zcrx::box_fd::make_box_inode(Arc::clone(ifq));
    let dentry = vfs::dcache::d_alloc_pseudo("[zcrx]", inode.clone(),
                                             &crate::anon_dname::ANON_INODE_OPS);
    let file = File::new(inode, dentry, OpenFlags::O_RDWR | OpenFlags::O_CLOEXEC);

    // The caller is told the descriptor BEFORE it is published, so a caller
    // that could not be told never has one it does not know about.
    let r = fdt.scm_install_fd(file, OpenFlags::O_CLOEXEC, cur.nofile_soft(), |fd| {
        c.set_export_fd(fd as u32);
        if uaccess::copy_to_user(arg, &c.to_bytes()).is_err() { return Err(vfs::VfsError::Efault); }
        Ok(())
    });
    match r {
        Ok(_) => 0,
        // The description was dropped rather than installed; its close path
        // released the user reference taken above.
        Err(e) => -(e as i32 as i64),
    }
}

/// `IORING_REGISTER_ZCRX_IFQ`. # C: O(N_pages)
pub fn register(inode: &Arc<IoUringInode>, arg: u64) -> i64 {
    // The queue can observe data destined for other tasks' sockets, and it
    // reconfigures a device queue; both are administrative.
    let Some(cur) = sched::live::current() else { return err(Errno::Eperm) };
    if !cur.has_cap(sched::cap::NET_ADMIN) { return err(Errno::Eperm); }
    if let Err(e) = admit_ring_flags(inode.flags) { return err(e); }

    let mut rb = [0u8; IFQ_REG_BYTES as usize];
    if uaccess::copy_from_user(&mut rb, arg).is_err() { return err(Errno::Efault); }
    let mut reg = IfqReg::from_bytes(&rb);

    let kind = match admit_ifq_reg(&mut reg, inode.flags) { Ok(k) => k, Err(e) => return err(e) };
    if kind == RegKind::Import { return import(inode, &mut reg, arg); }

    let mut rd = match read_region_desc(reg.region_ptr) { Ok(r) => r, Err(e) => return err(e) };
    let mut ab = [0u8; AREA_REG_BYTES as usize];
    if uaccess::copy_from_user(&mut ab, reg.area_ptr).is_err() { return err(Errno::Efault); }
    let mut area_reg = AreaReg::from_bytes(&ab);

    let mut notif = NotifDesc::default();
    if reg.notif_desc != 0 {
        let mut nb = [0u8; NOTIF_DESC_BYTES as usize];
        if uaccess::copy_from_user(&mut nb, reg.notif_desc).is_err() { return err(Errno::Efault); }
        notif = NotifDesc::from_bytes(&nb);
    }
    if let Err(e) = admit_notif_desc(&notif) { return err(e); }
    if let Err(e) = admit_area_reg(&area_reg, hal::PAGE_SIZE_BYTES) { return err(e); }

    let has_dev = matches!(kind, RegKind::Device { .. });
    let buf_shift = match admit_buf_len(reg.rx_buf_len, area_reg.len, has_dev, hal::PAGE_SIZE_BYTES) {
        Ok(s) => s, Err(e) => return err(e),
    };

    // The id is taken before anything is built, because the region's mmap
    // offset encodes it and the caller is told that offset.
    let id = match inode.zcrx_claim_id() { Ok(i) => i, Err(e) => return err(e) };

    reg.offsets = ZcrxOffsets::fill();
    let rq = match build_rq(&reg, &mut rd, &notif, id, inode.acct) {
        Ok(q) => q, Err(e) => { inode.zcrx_release_id(id); return err(e); }
    };
    let area = match build_area(&mut area_reg, buf_shift, inode.acct) {
        Ok(a) => a, Err(e) => { inode.zcrx_release_id(id); return err(e); }
    };

    let ifq = Arc::new(ZcrxIfq::new(id, area, rq, inode));
    ifq.set_notif(notif.type_mask, notif.user_data);

    if let RegKind::Device { if_idx, if_rxq } = kind {
        let rx_page_size = if reg.rx_buf_len != 0 { 1u32 << buf_shift } else { 0 };
        if let Err(e) = bind_device(&ifq, if_idx, if_rxq, rx_page_size) {
            inode.zcrx_release_id(id);
            return e;
        }
    }

    reg.zcrx_id = id;
    reg.rx_buf_len = 1u32 << buf_shift;
    let ok = uaccess::copy_to_user(arg, &reg.to_bytes()).is_ok()
        && uaccess::copy_to_user(reg.region_ptr, &rd.to_bytes()).is_ok()
        && uaccess::copy_to_user(reg.area_ptr, &area_reg.to_bytes()).is_ok();
    if !ok {
        ifq.close_queue();
        inode.zcrx_release_id(id);
        return err(Errno::Efault);
    }
    inode.zcrx_publish(id, ifq);
    0
}

/// `IORING_REGISTER_ZCRX_CTRL`. # C: per operation
pub fn ctrl(inode: &Arc<IoUringInode>, arg: u64, nr_args: u32) -> i64 {
    let mut b = [0u8; CTRL_BYTES as usize];
    if uaccess::copy_from_user(&mut b, arg).is_err() { return err(Errno::Efault); }
    let c = Ctrl::from_bytes(&b);
    if let Err(e) = admit_ctrl(&c, nr_args) { return err(e); }
    let Some(ifq) = inode.zcrx_lookup(c.zcrx_id) else { return err(Errno::Enxio) };
    let op = match admit_ctrl_op(&c) { Ok(o) => o, Err(e) => return err(e) };
    match op {
        ZCRX_CTRL_FLUSH_RQ => { ifq.flush_rq(); 0 }
        ZCRX_CTRL_ARM_NOTIFICATION => {
            let (ty, _) = c.arm_notif();
            match ifq.arm_notif(ty) { Ok(()) => 0, Err(e) => err(e) }
        }
        ZCRX_CTRL_EXPORT => export(&ifq, c, arg),
        _ => err(Errno::Eopnotsupp),
    }
}
