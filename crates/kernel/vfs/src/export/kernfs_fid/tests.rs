// The kernfs handle codec. Ungated module, so these actually compile and run.

use super::*;

/// The width is the contract: the cgroup-id reader in the service manager
/// passes `handle_bytes = 8` and never retries, so an encoder that needs more
/// fails it with EOVERFLOW and the cgroup id is unreadable.
#[test]
fn a_kernfs_handle_is_exactly_eight_bytes() {
    let mut buf = [0u8; 24];
    let (len, ty) = encode_kernfs_fid(0x0123_4567_89ab_cdef, &mut buf);
    assert_eq!(len, 8);
    assert_eq!(len, KERNFS_FID_LEN);
    assert_eq!(ty, HANDLE_TYPE_KERNFS);
}

/// The payload is the id little-endian, so userspace reading `f_handle` as a
/// `uint64_t` gets the same number `stat(2)` reports as `st_ino`.
#[test]
fn the_payload_is_the_id_little_endian() {
    let mut buf = [0u8; 8];
    encode_kernfs_fid(0x0011_2233_4455_6677, &mut buf);
    assert_eq!(buf, 0x0011_2233_4455_6677u64.to_le_bytes());
}

#[test]
fn encode_decode_round_trips_every_id_shape() {
    for id in [0u64, 1, 0x6000_0001, u32::MAX as u64, u64::MAX] {
        let mut buf = [0u8; 8];
        let (len, ty) = encode_kernfs_fid(id, &mut buf);
        let fid = decode_kernfs_fid(&buf[..len as usize]).expect("decodes");
        assert_eq!(fid.ino, id);
        assert_eq!(ty, HANDLE_TYPE_KERNFS);
        // No generation is encoded, so the handle matches any incarnation and
        // the filesystem's own decode decides whether the id still resolves.
        assert_eq!(fid.generation, GENERATION_ANY);
        assert_eq!(fid.parent, None);
    }
}

/// A payload of the wrong length is undecodable-but-well-formed: ESTALE, the
/// same answer the generic codec gives, never EINVAL.
#[test]
fn a_wrong_length_payload_is_stale() {
    for n in [0usize, 4, 7, 9, 12] {
        let buf = alloc::vec![0u8; n];
        assert_eq!(decode_kernfs_fid(&buf), Err(Errno::Estale), "len {n}");
    }
}
