// 457 statmount — one syscall, one file (docs/53 §0).
// statmount(req, buf, bufsize, flags): fill struct statmount for req->mnt_id.
// The returned `mask` field reports exactly which members are valid.
use syscall::{errno::Errno, SyscallArgs};
use alloc::vec::Vec;

// struct mnt_id_req { u32 size; u32 spare; u64 mnt_id; u64 param; }
const REQ_OFF_MNT_ID: u64 = 8;
const REQ_MIN_SIZE:   u64 = 24;

// struct statmount fixed-header field byte-offsets (Linux uapi).
const SM_OFF_SIZE:          usize = 0;
const SM_OFF_MASK:          usize = 8;
const SM_OFF_SB_MAGIC:      usize = 24;
const SM_OFF_FS_TYPE:       usize = 36;   // offset into str[]
const SM_OFF_MNT_ID:        usize = 40;
const SM_OFF_MNT_PARENT_ID: usize = 48;
const SM_OFF_MNT_ROOT:      usize = 104;  // offset into str[]
const SM_OFF_MNT_POINT:     usize = 108;  // offset into str[]
const SM_OFF_MNT_NS_ID:     usize = 112;
const SM_HDR_SIZE:          usize = 512;  // fixed part (incl. spare2[49]); str[] follows
const U32: usize = 4;
const U64: usize = 8;

// STATMOUNT_* mask bits — which fields are populated.
const STATMOUNT_SB_BASIC:  u64 = 0x01;
const STATMOUNT_MNT_BASIC: u64 = 0x02;
const STATMOUNT_MNT_ROOT:  u64 = 0x08;
const STATMOUNT_MNT_POINT: u64 = 0x10;
const STATMOUNT_FS_TYPE:   u64 = 0x20;
const STATMOUNT_MNT_NS_ID: u64 = 0x40;

/// `sys_statmount(req, buf, bufsize, flags)` — slot 457.
/// # C: O(N_mounts)
pub fn sys_statmount(args: &SyscallArgs) -> i64 {
    let req     = args.a0;
    let ubuf    = args.a1;
    let bufsize = args.a2 as usize;
    if req == 0 || req.saturating_add(REQ_MIN_SIZE) > hal::USER_VA_END {
        return -(Errno::Efault.as_i32() as i64);
    }
    // SAFETY: req range-checked for the 24-byte mnt_id_req; read mnt_id field.
    let mnt_id = unsafe { core::ptr::read_unaligned((req + REQ_OFF_MNT_ID) as *const u64) };
    let m = match ::vfs::mount::mount_by_id(mnt_id) {
        Some(m) => m, None => return -(Errno::Enoent.as_i32() as i64),
    };
    let parent = ::vfs::mount::parent_mnt_id(&m);

    // str[] area: fs-type name, mount root, mount point (each NUL-terminated).
    let mut strs: Vec<u8> = Vec::new();
    let fs_off    = strs.len() as u32; strs.extend_from_slice(m.fs.name().as_bytes());   strs.push(0);
    let root_off  = strs.len() as u32; strs.extend_from_slice(b"/");                      strs.push(0);
    let point_off = strs.len() as u32; strs.extend_from_slice(m.mount_point.as_bytes());  strs.push(0);

    let total = SM_HDR_SIZE + strs.len();
    if bufsize < total { return -(Errno::Eoverflow.as_i32() as i64); }
    if ubuf == 0 || ubuf.saturating_add(total as u64) > hal::USER_VA_END {
        return -(Errno::Efault.as_i32() as i64);
    }
    let mask = STATMOUNT_SB_BASIC | STATMOUNT_MNT_BASIC | STATMOUNT_MNT_ROOT
        | STATMOUNT_MNT_POINT | STATMOUNT_FS_TYPE | STATMOUNT_MNT_NS_ID;

    let mut buf = alloc::vec![0u8; total];
    buf[SM_OFF_SIZE..SM_OFF_SIZE + U32].copy_from_slice(&(total as u32).to_le_bytes());
    buf[SM_OFF_MASK..SM_OFF_MASK + U64].copy_from_slice(&mask.to_le_bytes());
    buf[SM_OFF_SB_MAGIC..SM_OFF_SB_MAGIC + U64].copy_from_slice(&m.fs.magic().to_le_bytes());
    buf[SM_OFF_FS_TYPE..SM_OFF_FS_TYPE + U32].copy_from_slice(&fs_off.to_le_bytes());
    buf[SM_OFF_MNT_ID..SM_OFF_MNT_ID + U64].copy_from_slice(&mnt_id.to_le_bytes());
    buf[SM_OFF_MNT_PARENT_ID..SM_OFF_MNT_PARENT_ID + U64].copy_from_slice(&parent.to_le_bytes());
    buf[SM_OFF_MNT_ROOT..SM_OFF_MNT_ROOT + U32].copy_from_slice(&root_off.to_le_bytes());
    buf[SM_OFF_MNT_POINT..SM_OFF_MNT_POINT + U32].copy_from_slice(&point_off.to_le_bytes());
    buf[SM_OFF_MNT_NS_ID..SM_OFF_MNT_NS_ID + U64].copy_from_slice(&m.ns.to_le_bytes());
    buf[SM_HDR_SIZE..].copy_from_slice(&strs);

    // SAFETY: ubuf range-checked for `total` bytes < USER_VA_END; copy into user AS.
    unsafe { core::ptr::copy_nonoverlapping(buf.as_ptr(), ubuf as *mut u8, total); }
    0
}
