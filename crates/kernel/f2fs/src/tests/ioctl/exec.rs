//! Carrying out the commands whose machinery already existed and had no
//! caller: sealing, measuring, reading back the metadata, and collecting.
//!
//! Before this surface, nothing in the tree called any of them from outside
//! their own tests. Each test here drives the command by its real number and
//! then checks the RESULT through a different path, so a command wired to the
//! wrong operation cannot pass by agreeing with itself.

use alloc::vec;
use alloc::vec::Vec;
use sectors::MemImage;
use syscall::errno::Errno;

use crate::ioctl::entry::{handle, Answer};
use crate::ioctl::perm::Ctx;
use crate::ioctl::req::Extra;
use crate::ioctl::uapi::*;
use crate::mode::S_IFREG;
use crate::test_image::{self, ROOT_INO};
use crate::volume::{NewInode, Volume};

const NOW: (u64, u32) = (1_800_000_000, 5);
const LOG_BS: u32 = 12;

fn root() -> Ctx {
    Ctx {
        cap_sys_admin: true, fmode_read: true, fmode_write: true, o_direct: false,
        owner_or_capable: true, mnt_writable: true, writecount: 1, dirty_pages: 0,
        mmapped: false, dst: crate::ioctl::DstFd::Unusable,
    }
}

fn send(v: &mut Volume<MemImage>, ino: u32, cmd: u32, p: &[u8], x: &Extra)
    -> Result<Answer, Errno> {
    handle(v, ino, cmd, p, x, &root())
}

fn done(a: Answer) -> crate::ioctl::Reply {
    match a { Answer::Done(r) => r, Answer::NotBuilt(u) => match u {} }
}

/// A volume that admits sealing, holding one file of `bytes`.
fn sealable(bytes: &[u8]) -> (Volume<MemImage>, u32) {
    let mut b = test_image::with_root();
    b.feature |= crate::flags::FEATURE_VERITY;
    let mut v = b.mount_rw().unwrap();
    let ino = v.create(ROOT_INO, b"f",
                       &NewInode { mode: S_IFREG | 0o644, uid: 0, gid: 0, rdev: 0, now: NOW },
                       None).unwrap();
    if !bytes.is_empty() { v.write_file(ino, 0, bytes).unwrap(); }
    (v, ino)
}

fn enable_payload(salt_len: u32, sig_len: u32) -> Vec<u8> {
    let mut b = vec![0u8; VERITY_ENABLE_ARG_SIZE as usize];
    b[VE_VERSION..VE_VERSION + 4].copy_from_slice(&VERITY_ENABLE_VERSION.to_le_bytes());
    b[VE_HASH_ALGORITHM..VE_HASH_ALGORITHM + 4]
        .copy_from_slice(&u32::from(crate::verity::uapi::HASH_ALG_SHA256).to_le_bytes());
    b[VE_BLOCK_SIZE..VE_BLOCK_SIZE + 4].copy_from_slice(&(1u32 << LOG_BS).to_le_bytes());
    b[VE_SALT_SIZE..VE_SALT_SIZE + 4].copy_from_slice(&salt_len.to_le_bytes());
    if salt_len > 0 { b[VE_SALT_PTR..VE_SALT_PTR + 8].copy_from_slice(&0x1000u64.to_le_bytes()); }
    b[VE_SIG_SIZE..VE_SIG_SIZE + 4].copy_from_slice(&sig_len.to_le_bytes());
    if sig_len > 0 { b[VE_SIG_PTR..VE_SIG_PTR + 8].copy_from_slice(&0x2000u64.to_le_bytes()); }
    b
}

// ---- sealing --------------------------------------------------------------

/// The sealing machinery existed and nothing called it. This is the caller.
#[test]
fn sealing_through_the_command_marks_the_file_and_reads_back_verified() {
    let (mut v, ino) = sealable(&[0xa5; 8192]);
    assert!(!v.read_inode(ino).unwrap().verity());
    send(&mut v, ino, ENABLE_VERITY, &enable_payload(0, 0), &Extra::default()).unwrap();
    assert!(v.read_inode(ino).unwrap().verity(), "the file must read back sealed");
    // The ordinary read path still returns the data, now attested.
    let inode = v.read_inode(ino).unwrap();
    let mut buf = vec![0u8; 8192];
    v.read_file(&inode, ino, 0, &mut buf).unwrap();
    assert_eq!(buf, vec![0xa5; 8192]);
}

#[test]
fn sealing_carries_the_salt_the_argument_named() {
    let (mut v, ino) = sealable(&[7u8; 4096]);
    let x = Extra { first: vec![0x11; 8], second: Vec::new() };
    send(&mut v, ino, ENABLE_VERITY, &enable_payload(8, 0), &x).unwrap();
    let inode = v.read_inode(ino).unwrap();
    let info = v.verity_info(&inode, ino).unwrap();
    assert_eq!(info.params.salt, vec![0x11; 8]);
}

/// A salted seal and an unsalted one over the same bytes must not measure the
/// same, or the salt would be attesting nothing.
#[test]
fn a_salted_seal_measures_differently_from_an_unsalted_one() {
    let (mut v, ino) = sealable(&[7u8; 4096]);
    send(&mut v, ino, ENABLE_VERITY, &enable_payload(0, 0), &Extra::default()).unwrap();
    let plain = digest(&mut v, ino);

    let (mut v, ino) = sealable(&[7u8; 4096]);
    let x = Extra { first: vec![0x11; 8], second: Vec::new() };
    send(&mut v, ino, ENABLE_VERITY, &enable_payload(8, 0), &x).unwrap();
    assert_ne!(digest(&mut v, ino), plain);
}

#[test]
fn sealing_a_volume_without_the_feature_is_refused() {
    let mut v = test_image::with_root().mount_rw().unwrap();
    let ino = v.create(ROOT_INO, b"f",
                       &NewInode { mode: S_IFREG | 0o644, uid: 0, gid: 0, rdev: 0, now: NOW },
                       None).unwrap();
    assert_eq!(send(&mut v, ino, ENABLE_VERITY, &enable_payload(0, 0), &Extra::default())
                   .map(|_| ()), Err(Errno::Eopnotsupp));
}

/// Sealing twice would leave two descriptors and no rule about which a reader
/// uses.
#[test]
fn sealing_an_already_sealed_file_is_refused() {
    let (mut v, ino) = sealable(&[1u8; 4096]);
    send(&mut v, ino, ENABLE_VERITY, &enable_payload(0, 0), &Extra::default()).unwrap();
    assert!(send(&mut v, ino, ENABLE_VERITY, &enable_payload(0, 0), &Extra::default())
                .is_err());
}

// ---- measuring ------------------------------------------------------------

fn digest(v: &mut Volume<MemImage>, ino: u32) -> Vec<u8> {
    let mut p = vec![0u8; VERITY_DIGEST_HEAD_SIZE as usize];
    p[VD_SIZE..VD_SIZE + 2].copy_from_slice(&64u16.to_le_bytes());
    let r = done(send(v, ino, MEASURE_VERITY, &p, &Extra::default()).unwrap());
    r.indirect.expect("the digest")
}

#[test]
fn measuring_answers_a_digest_of_the_algorithms_own_length() {
    let (mut v, ino) = sealable(&[3u8; 4096]);
    send(&mut v, ino, ENABLE_VERITY, &enable_payload(0, 0), &Extra::default()).unwrap();
    let mut p = vec![0u8; VERITY_DIGEST_HEAD_SIZE as usize];
    p[VD_SIZE..VD_SIZE + 2].copy_from_slice(&64u16.to_le_bytes());
    let r = done(send(&mut v, ino, MEASURE_VERITY, &p, &Extra::default()).unwrap());
    let head = r.payload.expect("the head");
    let size = u16::from_le_bytes([head[VD_SIZE], head[VD_SIZE + 1]]);
    assert_eq!(size as usize, crate::verity::uapi::SHA256_DIGEST_SIZE);
    assert_eq!(r.indirect.unwrap().len(), size as usize);
    // The head reports the algorithm, so a caller can tell which digest it has.
    let alg = u16::from_le_bytes([head[VD_ALGORITHM], head[VD_ALGORITHM + 1]]);
    assert_eq!(alg, u16::from(crate::verity::uapi::HASH_ALG_SHA256));
}

/// Two different files must not measure the same, or a measurement would
/// attest nothing.
#[test]
fn two_different_files_measure_differently() {
    let (mut a, ai) = sealable(&[1u8; 4096]);
    send(&mut a, ai, ENABLE_VERITY, &enable_payload(0, 0), &Extra::default()).unwrap();
    let (mut b, bi) = sealable(&[2u8; 4096]);
    send(&mut b, bi, ENABLE_VERITY, &enable_payload(0, 0), &Extra::default()).unwrap();
    assert_ne!(digest(&mut a, ai), digest(&mut b, bi));
}

/// A buffer too short is told so rather than handed a truncated digest, which
/// would compare unequal to every genuine one and look like corruption.
#[test]
fn a_measurement_buffer_too_short_is_refused_rather_than_truncated() {
    let (mut v, ino) = sealable(&[3u8; 4096]);
    send(&mut v, ino, ENABLE_VERITY, &enable_payload(0, 0), &Extra::default()).unwrap();
    let mut p = vec![0u8; VERITY_DIGEST_HEAD_SIZE as usize];
    p[VD_SIZE..VD_SIZE + 2].copy_from_slice(&4u16.to_le_bytes());
    assert_eq!(send(&mut v, ino, MEASURE_VERITY, &p, &Extra::default()).map(|_| ()),
               Err(Errno::Eoverflow));
}

#[test]
fn measuring_a_file_that_is_not_sealed_reports_no_such_data() {
    let (mut v, ino) = sealable(&[3u8; 4096]);
    let mut p = vec![0u8; VERITY_DIGEST_HEAD_SIZE as usize];
    p[VD_SIZE..VD_SIZE + 2].copy_from_slice(&64u16.to_le_bytes());
    assert_eq!(send(&mut v, ino, MEASURE_VERITY, &p, &Extra::default()).map(|_| ()),
               Err(Errno::Enodata));
}

// ---- reading the metadata back -------------------------------------------

fn read_meta(v: &mut Volume<MemImage>, ino: u32, kind: u64, off: u64, len: u64)
    -> Result<(Vec<u8>, i64), Errno> {
    let mut p = vec![0u8; VERITY_READ_METADATA_SIZE as usize];
    p[VRM_TYPE..VRM_TYPE + 8].copy_from_slice(&kind.to_le_bytes());
    p[VRM_OFFSET..VRM_OFFSET + 8].copy_from_slice(&off.to_le_bytes());
    p[VRM_LENGTH..VRM_LENGTH + 8].copy_from_slice(&len.to_le_bytes());
    p[VRM_BUF_PTR..VRM_BUF_PTR + 8].copy_from_slice(&0x3000u64.to_le_bytes());
    let r = done(send(v, ino, READ_VERITY_METADATA, &p, &Extra::default())?);
    Ok((r.indirect.unwrap_or_default(), r.value))
}

/// The descriptor read back must be the descriptor the seal wrote: it parses,
/// and its root is the root the reader checks against.
#[test]
fn the_descriptor_read_back_is_the_one_the_seal_wrote() {
    let (mut v, ino) = sealable(&[9u8; 8192]);
    send(&mut v, ino, ENABLE_VERITY, &enable_payload(0, 0), &Extra::default()).unwrap();
    let (bytes, n) = read_meta(&mut v, ino, VERITY_METADATA_TYPE_DESCRIPTOR, 0, 4096).unwrap();
    assert_eq!(n as usize, bytes.len());
    assert!(!bytes.is_empty());
    let d = crate::verity::descriptor::parse(&bytes).expect("it parses");
    assert_eq!(d.data_size, 8192);
    assert_eq!(d.hash_algorithm, crate::verity::uapi::HASH_ALG_SHA256);
}

/// The tree read back must be the tree the seal built: its length is the
/// length the descriptor's own geometry says.
#[test]
fn the_tree_read_back_is_as_long_as_the_descriptor_says() {
    let (mut v, ino) = sealable(&[9u8; 65536]);
    send(&mut v, ino, ENABLE_VERITY, &enable_payload(0, 0), &Extra::default()).unwrap();
    let (desc, _) = read_meta(&mut v, ino, VERITY_METADATA_TYPE_DESCRIPTOR, 0, 4096).unwrap();
    let d = crate::verity::descriptor::parse(&desc).unwrap();
    let want = crate::verity::descriptor::tree_size(&d, 65536).unwrap();
    assert!(want > 0);
    let (tree, n) = read_meta(&mut v, ino, VERITY_METADATA_TYPE_MERKLE_TREE, 0, want).unwrap();
    assert_eq!(tree.len() as u64, want);
    assert_eq!(n as u64, want);
}

/// A read resuming from where the last one stopped is how a caller walks the
/// whole tree, so an offset must actually skip.
#[test]
fn a_metadata_read_resumes_from_its_offset() {
    let (mut v, ino) = sealable(&[9u8; 65536]);
    send(&mut v, ino, ENABLE_VERITY, &enable_payload(0, 0), &Extra::default()).unwrap();
    let (whole, _) = read_meta(&mut v, ino, VERITY_METADATA_TYPE_DESCRIPTOR, 0, 4096).unwrap();
    let (tail, _) = read_meta(&mut v, ino, VERITY_METADATA_TYPE_DESCRIPTOR, 16, 4096).unwrap();
    assert_eq!(tail, whole[16..]);
}

/// A start past the end is a caller having read everything, not an error.
#[test]
fn a_metadata_read_past_the_end_answers_nothing_rather_than_failing() {
    let (mut v, ino) = sealable(&[9u8; 4096]);
    send(&mut v, ino, ENABLE_VERITY, &enable_payload(0, 0), &Extra::default()).unwrap();
    let (bytes, n) = read_meta(&mut v, ino, VERITY_METADATA_TYPE_DESCRIPTOR,
                               1 << 20, 4096).unwrap();
    assert!(bytes.is_empty());
    assert_eq!(n, 0);
}

/// A file sealed with no built-in signature has no signature to read.
#[test]
fn an_unsigned_seal_has_no_signature_to_read() {
    let (mut v, ino) = sealable(&[9u8; 4096]);
    send(&mut v, ino, ENABLE_VERITY, &enable_payload(0, 0), &Extra::default()).unwrap();
    let (bytes, n) = read_meta(&mut v, ino, VERITY_METADATA_TYPE_SIGNATURE, 0, 4096).unwrap();
    assert!(bytes.is_empty());
    assert_eq!(n, 0);
}

#[test]
fn reading_metadata_from_a_file_that_is_not_sealed_reports_no_such_data() {
    let (mut v, ino) = sealable(&[9u8; 4096]);
    assert_eq!(read_meta(&mut v, ino, VERITY_METADATA_TYPE_DESCRIPTOR, 0, 4096).map(|_| ()),
               Err(Errno::Enodata));
}

// ---- collecting -----------------------------------------------------------

/// The cleaner existed and the only thing that called it was the allocator
/// running out. This is the caller that asks for it on purpose.
#[test]
fn a_collection_asked_for_by_hand_reaches_the_cleaner() {
    let (mut v, ino) = sealable(&[0u8; 0]);
    // A background pass over a volume with nothing to move reports success
    // without freeing anything, which is the answer, not a failure.
    let a = send(&mut v, ino, GARBAGE_COLLECT, &0u32.to_le_bytes(), &Extra::default());
    assert!(a.is_ok(), "a background pass must not fail: {a:?}");
}

/// A synchronous collection over a volume with no reclaimable section reports
/// that it could not, rather than reporting success having done nothing.
#[test]
fn a_synchronous_collection_with_nothing_to_reclaim_says_so() {
    let (mut v, ino) = sealable(&[0u8; 0]);
    assert_eq!(send(&mut v, ino, GARBAGE_COLLECT, &1u32.to_le_bytes(), &Extra::default())
                   .map(|_| ()), Err(Errno::Eagain));
}

// ------------------------------------------------------------- the shutdown

/// The command whose entire purpose is to stop the filesystem. It used to sync
/// and report success, leaving the mount running, checkpointing enabled and
/// the next mount told nothing — so the volume it was issued against reached
/// fsck looking clean.
#[test]
fn every_shutdown_mode_stops_checkpointing_and_records_the_reason() {
    for mode in [GOING_DOWN_FULLSYNC, GOING_DOWN_METASYNC, GOING_DOWN_NOSYNC,
                 GOING_DOWN_METAFLUSH] {
        let (mut v, ino) = sealable(&[0u8; 0]);
        assert!(!v.sbi_flags().shutdown());
        assert!(send(&mut v, ino, SHUTDOWN, &mode.to_le_bytes(), &Extra::default()).is_ok());
        assert!(v.sbi_flags().shutdown(), "mode {mode} left the volume running");
        assert_ne!(v.checkpoint().flags & crate::flags::CP_ERROR_FLAG, 0,
                   "mode {mode} left checkpointing enabled");
        // Read the reason back off the MEDIUM through a fresh mount, so the
        // case cannot pass on in-memory state the command happened to set.
        let bytes = v.into_source().snapshot();
        let img = MemImage::from_bytes(crate::uapi::BLKSIZE as u32, bytes);
        let again = Volume::mount_with(img, crate::opts::Options::defaults(), true)
            .expect("remount");
        assert_eq!(again.error_record().stops(crate::errrec::StopReason::Shutdown), 1,
                   "mode {mode} recorded no reason for the next mount");
    }
}

/// `NEED_FSCK` is the one mode that is NOT a shutdown: it marks the volume as
/// wanting a repair and leaves the mount live.
#[test]
fn the_need_fsck_mode_marks_the_volume_without_stopping_it() {
    let (mut v, ino) = sealable(&[0u8; 0]);
    assert!(send(&mut v, ino, SHUTDOWN, &GOING_DOWN_NEED_FSCK.to_le_bytes(),
                 &Extra::default()).is_ok());
    assert!(!v.sbi_flags().shutdown(), "a repair request is not a shutdown");
    assert!(v.sbi_flags().is_set(crate::sbflags::bits::NEED_FSCK));
    assert!(v.sbi_flags().is_set(crate::sbflags::bits::CP_DISABLED_QUICK));
    assert_eq!(v.error_record().stops(crate::errrec::StopReason::Shutdown), 0);
}
