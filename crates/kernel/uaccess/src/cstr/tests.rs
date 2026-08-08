// The scan policy, driven against a fake address space.
//
// `Fixture::copy` reproduces exactly what the exception-table copy loops do on
// a real fault: bytes before the bad address are transferred, and the count of
// bytes NOT transferred comes back. That is the only property the scan may rely
// on, and modelling it here is what makes the MAPPING policy — not just the
// length policy — testable with no target and no user memory.

use super::*;

/// The address the boot probe used: in the user half, mapped by nothing.
const UNMAPPED: u64 = 0x7ffe_dead_0000;

struct Fixture {
    base:     u64,
    bytes:    alloc::vec::Vec<u8>,
    /// First address that faults. Everything at or above it is unmapped.
    hole_at:  u64,
}

impl Fixture {
    fn mapped(base: u64, bytes: &[u8]) -> Self {
        Self { base, bytes: bytes.to_vec(), hole_at: u64::MAX }
    }

    fn with_hole(base: u64, bytes: &[u8], hole_at: u64) -> Self {
        Self { base, bytes: bytes.to_vec(), hole_at }
    }

    /// Copy semantics of `raw_copy_from_user`: returns bytes NOT copied.
    fn copy(&self, dst: &mut [u8], src: u64) -> usize {
        for i in 0..dst.len() {
            let va = src + i as u64;
            if va >= self.hole_at { return dst.len() - i; }
            dst[i] = *self.bytes.get((va - self.base) as usize).unwrap_or(&0);
        }
        0
    }

    /// The truncating form — `strncpy_from_user`'s contract.
    fn scan(&self, max: u64) -> Result<alloc::vec::Vec<u8>, Errno> {
        scan_cstr(self.base, max, |d, s| self.copy(d, s))
    }

    /// The same read through the REAL `strndup_user` verdict, so a test here
    /// fails when that verdict changes.
    fn scan_dup(&self, n: u64) -> Result<alloc::vec::Vec<u8>, Errno> {
        strndup_verdict(self.scan(n)?, n)
    }
}

// ---- length policy (the contract the previous owner of this scan held) ----

#[test]
fn reads_a_full_path_not_capped_at_64() {
    let mut buf =
        b"/usr/lib/systemd/user-environment-generators/30-systemd-environment-d-generator".to_vec();
    assert_eq!(buf.len(), 79);
    buf.push(0);
    let f = Fixture::mapped(0x1000, &buf);
    let got = f.scan(4096).expect("resolves");
    assert_eq!(got.len(), 79);
    assert_eq!(&got[..], &buf[..79]);
}

#[test]
fn boundary_64_and_65() {
    let mut a = alloc::vec![b'a'; 64]; a.push(0);
    assert_eq!(Fixture::mapped(0x1000, &a).scan(4096).unwrap().len(), 64);
    let mut b = alloc::vec![b'b'; 65]; b.push(0);
    assert_eq!(Fixture::mapped(0x1000, &b).scan(4096).unwrap().len(), 65);
}

/// The reference `strncpy_from_user` reports the caller's own bound by the
/// LENGTH it returns, not by an error: a name that fills the buffer is a
/// successful read of that many bytes, and the caller decides what it means.
#[test]
fn no_nul_within_count_returns_the_full_count() {
    let buf = alloc::vec![b'x'; 16];
    assert_eq!(Fixture::mapped(0x1000, &buf).scan(8), Ok(alloc::vec![b'x'; 8]));
}

/// `strndup_user` is the layer that turns that same read into a refusal, so a
/// path that does not terminate never resolves as a truncated prefix.
#[test]
fn no_nul_within_n_is_enametoolong_through_strndup() {
    let buf = alloc::vec![b'x'; 16];
    assert_eq!(Fixture::mapped(0x1000, &buf).scan_dup(8), Err(Errno::Enametoolong));
}

/// The boundary between the two: `n - 1` bytes plus a NUL is the longest
/// string `strndup_user` admits.
#[test]
fn strndup_admits_exactly_n_minus_one_bytes() {
    let mut ok = alloc::vec![b'y'; 7]; ok.push(0);
    assert_eq!(Fixture::mapped(0x1000, &ok).scan_dup(8).unwrap().len(), 7);
    let mut too = alloc::vec![b'y'; 8]; too.push(0);
    assert_eq!(Fixture::mapped(0x1000, &too).scan_dup(8), Err(Errno::Enametoolong));
}

#[test]
fn base_past_user_end_is_efault() {
    assert_eq!(scan_cstr(USER_VA_END, 4096, |d, _| { d.fill(b'a'); 0 }), Err(Errno::Efault));
    assert_eq!(scan_cstr(USER_VA_END + 1, 4096, |d, _| { d.fill(b'a'); 0 }), Err(Errno::Efault));
}

#[test]
fn walking_off_user_end_before_nul_is_efault() {
    let base = USER_VA_END - 4;
    assert_eq!(scan_cstr(base, 4096, |d, _| { d.fill(b'a'); 0 }), Err(Errno::Efault));
}

#[test]
fn a_nul_just_below_user_end_still_resolves() {
    // The clamp to USER_VA_END must not turn a legal string that ends on the
    // last user byte into a fault.
    let base = USER_VA_END - 4;
    let got = scan_cstr(base, 4096, |d, s| {
        for i in 0..d.len() { d[i] = if s + i as u64 == USER_VA_END - 1 { 0 } else { b'a' }; }
        0
    });
    assert_eq!(got, Ok(alloc::vec![b'a'; 3]));
}

// ---- mapping policy: a read that faults is EFAULT, never a kernel fault ----

#[test]
fn an_unmapped_base_is_efault_not_a_partial_string() {
    // The exact shape that killed the boot: an address inside the user half
    // that nothing maps. Nothing is readable, so nothing may be returned.
    let f = Fixture::with_hole(UNMAPPED, b"ignored\0", UNMAPPED);
    assert_eq!(f.scan(4096), Err(Errno::Efault));
}

#[test]
fn an_unmapped_page_mid_string_is_efault() {
    // Readable text with no terminator, running into a hole one page in. The
    // prefix must NOT come back as a successful short string.
    let base = 0x7ffe_dead_0000 - 0x1000;
    let f = Fixture::with_hole(base, &alloc::vec![b'a'; 0x2000], UNMAPPED);
    assert_eq!(f.scan(0x2000), Err(Errno::Efault));
}

#[test]
fn a_nul_before_the_hole_never_reaches_it() {
    // Terminated inside the readable page: the scan must stop there and never
    // ask for the unmapped one, so a valid string beside a hole still works.
    let base = UNMAPPED - 0x1000;
    let mut bytes = b"/etc/passwd".to_vec();
    bytes.push(0);
    let f = Fixture::with_hole(base, &bytes, UNMAPPED);
    assert_eq!(f.scan(4096).unwrap(), b"/etc/passwd".to_vec());
}

#[test]
fn a_nul_in_the_last_readable_byte_resolves() {
    // The terminator sits in the final byte before the hole. It is readable,
    // so the string resolves and the fault is never provoked.
    let base = UNMAPPED - 4;
    let f = Fixture::with_hole(base, b"abc\0", UNMAPPED);
    assert_eq!(f.scan(4096).unwrap(), b"abc".to_vec());
}

#[test]
fn a_string_spanning_a_page_boundary_is_read_whole() {
    // Page-at-a-time reading must not truncate at the boundary. 40 bytes
    // starting 20 below a page edge crosses it.
    let base = 0x2_0000 - 20;
    let mut bytes = alloc::vec![b'z'; 40];
    bytes.push(0);
    let f = Fixture::mapped(base, &bytes);
    assert_eq!(f.scan(4096).unwrap().len(), 40);
}

#[test]
fn the_scan_stops_at_the_hole_and_asks_for_no_more() {
    // A fault must end the walk, not be retried page after page until max_len.
    // Counting the copy calls pins that: one for the readable page, one that
    // faults, and no more.
    let base = UNMAPPED - 0x1000;
    let mut calls = 0usize;
    let r = scan_cstr(base, 0x4000, |d, s| {
        calls += 1;
        for i in 0..d.len() {
            let va = s + i as u64;
            if va >= UNMAPPED { return d.len() - i; }
            d[i] = b'q';
        }
        0
    });
    assert_eq!(r, Err(Errno::Efault));
    assert_eq!(calls, 2);
}

#[test]
fn a_null_pointer_is_efault_through_the_live_reader() {
    // `strncpy_from_user` leans on the range check inside the copy for NULL, so
    // no caller needs its own test for it.
    assert_eq!(strncpy_from_user(0, 16), Err(Errno::Efault));
}
