//! Scalar io_uring RWF_SYNC/RWF_DSYNC over a real ext4 file.

use std::alloc::{alloc_zeroed, dealloc, Layout};
use std::fs::{metadata, remove_file, set_permissions, OpenOptions};
use std::io;
use std::os::fd::AsRawFd;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use support::{fail_errno, report, Verdict};

const PROBE: &str = "io_uring_ext4_probe";
const PATH: &str = "/var/tmp/oxide-io-uring-ext4.bin";
const PAGE: usize = 4096;
const ENTRIES: u32 = 4;
const IO_URING_SETUP: libc::c_long = 425;
const IO_URING_ENTER: libc::c_long = 426;
const IORING_OP_WRITE: u8 = 23;
const RWF_DSYNC: u32 = 0x0000_0002;
const RWF_SYNC: u32 = 0x0000_0004;
const RING_SQ_HEAD: usize = 0;
const RING_SQ_TAIL: usize = 4;
const RING_CQ_HEAD: usize = 8;
const RING_CQ_TAIL: usize = 12;
const PARAM_SQ_OFF: usize = 40;
const PARAM_CQ_OFF: usize = 80;
const OFF_SQES: libc::off_t = 0x1000_0000;
const RING_BYTES: usize = PAGE;

#[repr(C)]
struct RingParams { bytes: [u8; 120] }

struct Ring {
    fd: libc::c_int,
    rings: *mut u8,
    sqes: *mut u8,
    sq_array: usize,
    cqes: usize,
    sq_entries: u32,
    cq_entries: u32,
}

impl Ring {
    fn open() -> io::Result<Self> {
        let mut params = RingParams { bytes: [0; 120] };
        // SAFETY: libc syscall receives the valid entry count and writable
        // pointer to the ABI-sized zeroed parameter structure for this call.
        let fd = unsafe { libc::syscall(IO_URING_SETUP, ENTRIES, &mut params.bytes) as libc::c_int };
        if fd < 0 { return Err(io::Error::last_os_error()); }
        // SAFETY: the returned ring fd owns one kernel-provided shared region;
        // mmap arguments match the region geometry exposed by this kernel.
        let rings = unsafe { libc::mmap(std::ptr::null_mut(), RING_BYTES,
            libc::PROT_READ | libc::PROT_WRITE, libc::MAP_SHARED, fd, 0) } as *mut u8;
        if rings == libc::MAP_FAILED as *mut u8 {
            // SAFETY: fd was returned by io_uring_setup and is not shared.
            unsafe { libc::close(fd); }
            return Err(io::Error::last_os_error());
        }
        let sqes = unsafe { libc::mmap(std::ptr::null_mut(), RING_BYTES,
            libc::PROT_READ | libc::PROT_WRITE, libc::MAP_SHARED, fd, OFF_SQES) } as *mut u8;
        if sqes == libc::MAP_FAILED as *mut u8 {
            unsafe { libc::munmap(rings.cast(), RING_BYTES); libc::close(fd); }
            return Err(io::Error::last_os_error());
        }
        let u32_at = |off: usize| -> u32 {
            let mut bytes = [0u8; 4];
            bytes.copy_from_slice(&params.bytes[off..off + 4]);
            u32::from_ne_bytes(bytes)
        };
        let sq_array = u32_at(PARAM_SQ_OFF + 24) as usize;
        let cqes = u32_at(PARAM_CQ_OFF + 20) as usize;
        Ok(Self { fd, rings, sqes, sq_array, cqes,
            sq_entries: u32_at(0), cq_entries: u32_at(4) })
    }

    fn submit_write(&self, file: libc::c_int, data: *mut u8, flags: u32) -> io::Result<usize> {
        // SAFETY: all pointers below refer to the live shared ring mapping;
        // this process is the sole submitter and publishes the SQ tail last.
        unsafe {
            let sq_head = self.rings.add(RING_SQ_HEAD).cast::<u32>().read_volatile();
            let sq_tail = self.rings.add(RING_SQ_TAIL).cast::<u32>();
            let entries = self.sq_entries;
            let mask = entries.checked_sub(1).ok_or_else(|| io::Error::from_raw_os_error(libc::EINVAL))?;
            let slot = (sq_head & mask) as usize;
            let sq_array = self.rings.add(self.sq_array).cast::<u32>();
            let sqe = self.sqes.add(slot * 64);
            std::ptr::write_bytes(sqe, 0, 64);
            sqe.write(IORING_OP_WRITE);
            sqe.add(4).cast::<i32>().write(file);
            sqe.add(8).cast::<u64>().write(0);
            sqe.add(16).cast::<u64>().write(data as u64);
            sqe.add(24).cast::<u32>().write(PAGE as u32);
            sqe.add(28).cast::<u32>().write(flags);
            sqe.add(32).cast::<u64>().write(flags as u64);
            sq_array.add((sq_head & mask) as usize).write_volatile(slot as u32);
            sq_tail.write_volatile(sq_head + 1);
            let submitted = libc::syscall(IO_URING_ENTER, self.fd, 1usize, 1usize, 0usize, 0usize, 0usize);
            if submitted < 1 { return Err(io::Error::last_os_error()); }
            let cq_head = self.rings.add(RING_CQ_HEAD).cast::<u32>();
            let head = cq_head.read_volatile();
            let cq_tail = self.rings.add(RING_CQ_TAIL).cast::<u32>().read_volatile();
            if cq_tail == head { return Err(io::Error::from_raw_os_error(libc::EIO)); }
            let cqe = self.rings.add(self.cqes + ((head & (self.cq_entries - 1)) as usize * 16));
            let result = cqe.add(8).cast::<i32>().read_volatile();
            cq_head.write_volatile(head + 1);
            if result < 0 { return Err(io::Error::from_raw_os_error(-result)); }
            Ok(result as usize)
        }
    }
}

impl Drop for Ring {
    fn drop(&mut self) {
        // SAFETY: this mapping and fd are owned exclusively by this Ring.
        unsafe { libc::munmap(self.sqes.cast(), RING_BYTES); libc::munmap(self.rings.cast(), RING_BYTES); libc::close(self.fd); }
    }
}

fn main() -> std::process::ExitCode { report(PROBE, run()) }

fn run() -> Verdict {
    let _ = remove_file(PATH);
    let file = match OpenOptions::new().read(true).write(true).create(true).open(PATH) {
        Ok(file) => file,
        Err(_) => return fail_errno("create"),
    };
    if let Err(_) = file.set_len(PAGE as u64) { return fail_errno("set-length"); }
    let _ = set_permissions(PATH, std::fs::Permissions::from_mode(0o600));
    let before = match metadata(Path::new(PATH)) {
        Ok(meta) => meta.modified().ok(), Err(_) => None,
    };
    let layout = Layout::from_size_align(PAGE, PAGE).expect("probe layout");
    // SAFETY: layout has nonzero size and a valid power-of-two alignment; the
    // allocation remains live until every SQE has completed.
    let data = unsafe { alloc_zeroed(layout) };
    if data.is_null() { return fail_errno("aligned-buffer"); }
    let ring = match Ring::open() {
        Ok(ring) => ring,
        Err(_) => { unsafe { dealloc(data, layout); } return fail_errno("io-uring-setup"); }
    };
    let fd = file.as_raw_fd();
    let first = ring.submit_write(fd, data, RWF_DSYNC);
    let second = first.as_ref().ok().map(|_| ring.submit_write(fd, data, RWF_SYNC));
    // SAFETY: both submitted operations have returned a CQE before the buffer
    // is released, and this allocation is owned only by this probe.
    unsafe { dealloc(data, layout); }
    if !matches!(first, Ok(PAGE)) || !matches!(second, Some(Ok(PAGE))) {
        return fail_errno("scalar-rwf-write");
    }
    if file.sync_all().is_err() { return fail_errno("final-sync"); }
    let after = metadata(Path::new(PATH)).ok().and_then(|meta| meta.modified().ok());
    let _ = remove_file(PATH);
    if before.is_some() && after < before { return support::fail("timestamp moved backwards"); }
    Verdict::Pass("scalar io_uring RWF_DSYNC/RWF_SYNC ext4 write".into())
}
