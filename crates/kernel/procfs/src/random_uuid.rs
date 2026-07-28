// Random-UUID bodies for `/proc/sys/kernel/random/{uuid,boot_id}` and
// `/sys/kernel/random/{uuid,boot_id}`.
//
// Linux `drivers/char/random.c` `proc_do_uuid` (the `random_table` handler for
// BOTH leaves) distinguishes them by `.data`:
//   * `uuid`    — registered with NO `.data`, so every read takes the
//     `if (!uuid) { uuid = tmp_uuid; generate_random_uuid(uuid); }` branch:
//     a FRESH v4 UUID per read, from a stack buffer.
//   * `boot_id` — registered with `.data = &sysctl_bootid`, so the first read
//     generates under `bootid_spinlock` and every later read re-formats that
//     same 16 bytes: stable for the life of the boot.
// Both are mode 0444 and both render through `proc_dostring`, which appends the
// trailing newline — 36 UUID chars + '\n'.
//
// Bit-setting is Linux `lib/uuid.c` `generate_random_uuid`: 16 random bytes,
// version 4 in the high nibble of byte 6, DCE variant in the top two bits of
// byte 8. Rendering is `%pU` (`lib/vsprintf.c` `uuid_string`, default
// big-endian/lowercase): the 16 bytes in index order, lowercase hex, hyphens
// after bytes 4, 6, 8 and 10.
//
// UNGATED on purpose: the version/variant/format decision logic is the part
// worth testing, and a `#[cfg(target_os = "oxide-kernel")]` module's tests
// compile out silently.

use alloc::vec::Vec;

/// `UUID_SIZE` (`include/linux/uuid.h`).
pub const UUID_BYTES: usize = 16;
/// `UUID_STRING_LEN` (`include/linux/uuid.h`) — 36 chars, no NUL, no newline.
pub const UUID_STRING_LEN: usize = 36;
/// `proc_dostring` read shape: the string plus its terminating newline.
pub const UUID_LINE_LEN: usize = UUID_STRING_LEN + 1;

/// Byte carrying the UUID version nibble (`lib/uuid.c`: `uuid[6]`).
const VERSION_BYTE: usize = 6;
/// Mask retaining the random low nibble of `VERSION_BYTE`.
const VERSION_KEEP_MASK: u8 = 0x0f;
/// Version 4 ("truly random generation") in the high nibble.
const VERSION_4: u8 = 0x40;
/// Byte carrying the UUID variant bits (`lib/uuid.c`: `uuid[8]`).
const VARIANT_BYTE: usize = 8;
/// Mask retaining the random low six bits of `VARIANT_BYTE`.
const VARIANT_KEEP_MASK: u8 = 0x3f;
/// RFC 4122 / DCE variant (`10x` in the top bits).
const VARIANT_DCE: u8 = 0x80;

/// Byte index of each hyphen group boundary in `%pU` output.
const GROUP_ENDS: [usize; 4] = [4, 6, 8, 10];

/// Stamp version 4 + DCE variant over otherwise-random bytes — `lib/uuid.c`
/// `generate_random_uuid`. # C: O(1)
pub fn set_uuid_v4_bits(uuid: &mut [u8; UUID_BYTES]) {
    uuid[VERSION_BYTE] = (uuid[VERSION_BYTE] & VERSION_KEEP_MASK) | VERSION_4;
    uuid[VARIANT_BYTE] = (uuid[VARIANT_BYTE] & VARIANT_KEEP_MASK) | VARIANT_DCE;
}

/// Lowercase hex digit of `n`'s low nibble. # C: O(1)
fn hex_nibble(n: u8) -> u8 {
    match n & 0x0f {
        v @ 0..=9 => b'0' + v,
        v => b'a' + (v - 10),
    }
}

/// Render `uuid` as `%pU` plus the `proc_dostring` newline —
/// `UUID_LINE_LEN` bytes. # C: O(UUID_BYTES)
pub fn format_uuid_line(uuid: &[u8; UUID_BYTES]) -> Vec<u8> {
    let mut out = Vec::with_capacity(UUID_LINE_LEN);
    for (i, b) in uuid.iter().copied().enumerate() {
        out.push(hex_nibble(b >> 4));
        out.push(hex_nibble(b));
        if GROUP_ENDS.contains(&(i + 1)) { out.push(b'-'); }
    }
    out.push(b'\n');
    out
}

/// 16 CSPRNG bytes with the v4 version/variant stamped in. The only randomness
/// source is `crng` (`27`); there is no second generator. # C: O(1)
pub fn generate_uuid_bytes() -> [u8; UUID_BYTES] {
    let mut uuid = [0u8; UUID_BYTES];
    crng::fill(&mut uuid);
    set_uuid_v4_bits(&mut uuid);
    uuid
}

/// One read's worth of `/proc/sys/kernel/random/uuid` — a FRESH v4 UUID, as
/// Linux's `.data`-less `proc_do_uuid` leaf does. # C: O(1)
pub fn generate_uuid_line() -> Vec<u8> {
    format_uuid_line(&generate_uuid_bytes())
}

/// The two inode shapes the `random_table` leaves need. Kept beside the value
/// logic so the "which leaf is regenerated" decision lives in ONE place — the
/// registration sites (`ctl.rs`, `static_files.rs`) only choose a path.
#[cfg(any(target_os = "oxide-kernel", test))]
mod inodes {
    use super::*;
    use alloc::boxed::Box;
    use vfs::{Ino, InodeRef, StaticFileInode};

    /// The once-per-boot `boot_id` body, leaked for the life of the kernel —
    /// Linux's `sysctl_bootid`. Called ONCE on the boot path; both the
    /// `/proc/sys` and `/sys` leaves share the returned slice, so they cannot
    /// disagree. # C: O(1)
    pub fn leak_boot_id_line() -> &'static [u8] {
        Box::leak(format_uuid_line(&generate_uuid_bytes()).into_boxed_slice())
    }

    /// `boot_id` inode: a fixed body, stable for every reader all boot.
    /// # C: O(1)
    pub fn make_boot_id_inode(line: &'static [u8]) -> InodeRef { StaticFileInode::new(line) }

    /// `uuid` inode: the body is generated on EVERY read, so no two readers —
    /// and no two reads by one reader — share a UUID. # C: O(1)
    pub fn make_uuid_inode(ino: Ino) -> InodeRef {
        crate::dyn_file::make_gen_file(ino, generate_uuid_line)
    }
}

#[cfg(any(target_os = "oxide-kernel", test))]
pub use inodes::{leak_boot_id_line, make_boot_id_inode, make_uuid_inode};

#[cfg(test)]
mod tests {
    use super::*;

    fn is_lower_hex(b: u8) -> bool { b.is_ascii_digit() || (b'a'..=b'f').contains(&b) }

    /// Full `%pU` v4 shape check: length, hyphen positions, lowercase hex,
    /// version nibble, RFC 4122 variant.
    fn assert_v4_line(line: &[u8]) {
        assert_eq!(line.len(), UUID_LINE_LEN, "uuid line length");
        assert_eq!(line[UUID_STRING_LEN], b'\n', "trailing newline");
        for i in 0..UUID_STRING_LEN {
            match i {
                8 | 13 | 18 | 23 => assert_eq!(line[i], b'-', "hyphen at {i}"),
                _ => assert!(is_lower_hex(line[i]), "lowercase hex at {i}: {:?}", line[i] as char),
            }
        }
        assert_eq!(line[14], b'4', "version nibble");
        assert!(matches!(line[19], b'8' | b'9' | b'a' | b'b'), "variant nibble: {:?}", line[19] as char);
    }

    #[test]
    fn version_and_variant_bits_survive_all_ones_and_all_zeros() {
        let mut ones = [0xffu8; UUID_BYTES];
        set_uuid_v4_bits(&mut ones);
        assert_eq!(ones[VERSION_BYTE], 0x4f);
        assert_eq!(ones[VARIANT_BYTE], 0xbf);
        let mut zeros = [0u8; UUID_BYTES];
        set_uuid_v4_bits(&mut zeros);
        assert_eq!(zeros[VERSION_BYTE], 0x40);
        assert_eq!(zeros[VARIANT_BYTE], 0x80);
        // Every other byte is left alone.
        for (i, b) in ones.iter().copied().enumerate() {
            if i != VERSION_BYTE && i != VARIANT_BYTE { assert_eq!(b, 0xff, "byte {i} clobbered"); }
        }
    }

    #[test]
    fn format_matches_pu_byte_order() {
        let mut uuid = [0u8; UUID_BYTES];
        for (i, b) in uuid.iter_mut().enumerate() { *b = i as u8 * 0x11; }
        set_uuid_v4_bits(&mut uuid);
        let line = format_uuid_line(&uuid);
        assert_eq!(&line[..], b"00112233-4455-4677-8899-aabbccddeeff\n");
        assert_v4_line(&line);
    }

    #[test]
    fn every_render_is_a_wellformed_v4_uuid() {
        for _ in 0..64 { assert_v4_line(&generate_uuid_line()); }
    }

    /// Read a whole leaf body through the inode the boot path registers.
    fn read_leaf(inode: &vfs::InodeRef) -> Vec<u8> {
        let mut buf = [0u8; UUID_LINE_LEN + 8];
        let n = inode.read(0, &mut buf).expect("uuid leaf read");
        assert_eq!(n, UUID_LINE_LEN, "proc_dostring shape: 36 chars + newline");
        buf[..n].to_vec()
    }

    #[test]
    fn uuid_leaf_regenerates_on_every_read() {
        let inode = make_uuid_inode(crate::ids::RANDOM_UUID);
        let first = read_leaf(&inode);
        let second = read_leaf(&inode);
        assert_v4_line(&first);
        assert_v4_line(&second);
        assert_ne!(first, second, "`uuid` has no .data in Linux: fresh UUID per read");
    }

    #[test]
    fn boot_id_leaf_is_stable_across_reads() {
        let inode = make_boot_id_inode(leak_boot_id_line());
        let first = read_leaf(&inode);
        let second = read_leaf(&inode);
        assert_v4_line(&first);
        assert_eq!(first, second, "`boot_id` binds .data = &sysctl_bootid: stable all boot");
    }

    #[test]
    fn successive_renders_differ() {
        let first = generate_uuid_line();
        let second = generate_uuid_line();
        assert_ne!(first, second, "uuid must be regenerated per read");
        // 64 draws with no repeat: a cached body would collide immediately.
        let mut seen = alloc::vec::Vec::new();
        for _ in 0..64 {
            let line = generate_uuid_line();
            assert!(!seen.contains(&line), "uuid repeated across reads");
            seen.push(line);
        }
    }
}
