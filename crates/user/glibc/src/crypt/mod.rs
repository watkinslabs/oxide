//! crypt — glibc-ABI password hashing (docs/59§6 G17a). $5$ (sha256crypt) and
//! $6$ (sha512crypt) per Drepper 2007; the hash cores live in the workspace
//! `crypt` crate (aliased `libcrypt`). Pure `crypt_hash` assembles the full
//! `$id$[rounds=N$]salt$digest` setting string; crypt/crypt_r are the C ABI.
use alloc::string::String;

// DES block cipher + setkey/encrypt/ecb_crypt/cbc_crypt/des_setparity (G17a).
pub mod des;
#[cfg(feature = "freestanding")]
pub mod des_api;

const ROUNDS_DEFAULT: u32 = 5000;
const ROUNDS_MIN: u32 = 1000;
const ROUNDS_MAX: u32 = 999_999_999;
const SALT_MAX: usize = 16;

struct Setting<'a> { id: u8, rounds: u32, rounds_explicit: bool, salt: &'a [u8] }

// Parse a `$id$[rounds=N$]salt[...]` setting; salt truncated to 16, stops at '$'.
fn parse_setting(s: &[u8]) -> Option<Setting<'_>> {
    let rest = s.strip_prefix(b"$")?;
    let id = *rest.first()?;
    if id != b'5' && id != b'6' { return None; }
    let mut rest = rest.get(1..)?.strip_prefix(b"$")?;
    let mut rounds = ROUNDS_DEFAULT;
    let mut rounds_explicit = false;
    if let Some(r) = rest.strip_prefix(b"rounds=") {
        let mut n: u64 = 0;
        let mut k = 0;
        while k < r.len() && r[k].is_ascii_digit() { n = n * 10 + (r[k] - b'0') as u64; k += 1; }
        if k == 0 || r.get(k) != Some(&b'$') { return None; }
        rounds = n.min(ROUNDS_MAX as u64) as u32;
        rounds_explicit = true;
        rest = &r[k + 1..];
    }
    // salt = bytes up to next '$', capped at 16
    let end = rest.iter().position(|&c| c == b'$').unwrap_or(rest.len()).min(SALT_MAX);
    Some(Setting { id, rounds: rounds.clamp(ROUNDS_MIN, ROUNDS_MAX), rounds_explicit, salt: &rest[..end] })
}

/// Compute the full crypt setting+digest string for `key` against `setting`.
/// Returns None for an unsupported/malformed setting.
/// # C: char *crypt(const char *key, const char *setting) result body
pub(crate) fn crypt_hash(key: &[u8], setting: &[u8]) -> Option<String> {
    let s = parse_setting(setting)?;
    let digest = match s.id {
        b'5' => libcrypt::sha256::sha256crypt(key, s.salt, s.rounds),
        _ => libcrypt::sha512::sha512crypt(key, s.salt, s.rounds),
    };
    let mut out = String::with_capacity(160);
    out.push('$');
    out.push(s.id as char);
    out.push('$');
    if s.rounds_explicit {
        out.push_str("rounds=");
        push_u32(&mut out, s.rounds);
        out.push('$');
    }
    for &b in s.salt { out.push(b as char); } // salt is ASCII (crypt alphabet)
    out.push('$');
    out.push_str(&digest);
    Some(out)
}

fn push_u32(out: &mut String, mut v: u32) {
    let mut buf = [0u8; 10];
    let mut i = buf.len();
    loop { i -= 1; buf[i] = b'0' + (v % 10) as u8; v /= 10; if v == 0 { break; } }
    for &b in &buf[i..] { out.push(b as char); }
}

#[cfg(feature = "freestanding")]
pub use imp::*;

#[cfg(feature = "freestanding")]
mod imp {
    use super::*;
    use crate::internal::errno;
    use core::cell::UnsafeCell;

    const EINVAL: i32 = 22;
    const OUTLEN: usize = 256;

    struct OutBuf(UnsafeCell<[u8; OUTLEN]>);
    // SAFETY: crypt returns a pointer to this process-global buffer; contents
    // valid until the next crypt call (matching glibc's static-buffer crypt).
    unsafe impl Sync for OutBuf {}
    static OUT: OutBuf = OutBuf(UnsafeCell::new([0; OUTLEN]));

    // Write `s` + NUL into `dst` (≥ OUTLEN bytes); returns dst as a C string.
    fn store(dst: *mut u8, s: &str) -> *mut u8 {
        // SAFETY: dst points to at least OUTLEN bytes; s.len() < OUTLEN by
        // construction (id+rounds+16 salt+86 digest ≈ 120 < 256).
        unsafe {
            let n = s.len().min(OUTLEN - 1);
            core::ptr::copy_nonoverlapping(s.as_ptr(), dst, n);
            *dst.add(n) = 0;
            dst
        }
    }

    unsafe fn as_bytes<'a>(p: *const u8) -> &'a [u8] {
        // SAFETY: p is a NUL-terminated C string; scan to the terminator and
        // borrow the bytes before it.
        unsafe {
            if p.is_null() { return &[]; }
            let mut n = 0;
            while *p.add(n) != 0 { n += 1; }
            core::slice::from_raw_parts(p, n)
        }
    }

    // # C: char *crypt(const char *key, const char *setting)
    #[no_mangle]
    pub unsafe extern "C" fn crypt(key: *const u8, setting: *const u8) -> *mut u8 {
        // SAFETY: key/setting are NUL-terminated C strings; result goes to the
        // process-global OUT buffer. NULL + EINVAL on a bad setting.
        unsafe {
            match crypt_hash(as_bytes(key), as_bytes(setting)) {
                Some(s) => store(OUT.0.get() as *mut u8, &s),
                None => { errno::set(EINVAL); core::ptr::null_mut() }
            }
        }
    }

    // # C: char *crypt_r(const char *key, const char *setting, struct crypt_data *data)
    #[no_mangle]
    pub unsafe extern "C" fn crypt_r(key: *const u8, setting: *const u8, data: *mut u8) -> *mut u8 {
        // SAFETY: key/setting are C strings; data is a caller-owned struct
        // crypt_data (≫ OUTLEN bytes); write the result at its start and return
        // that pointer (reentrant — no shared state).
        unsafe {
            match crypt_hash(as_bytes(key), as_bytes(setting)) {
                Some(s) => store(data, &s),
                None => { errno::set(EINVAL); core::ptr::null_mut() }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sha512_full_setting_drepper() {
        let out = crypt_hash(b"Hello world!", b"$6$saltstring").unwrap();
        assert_eq!(out, "$6$saltstring$svn8UoSVapNtMuq1ukKS4tPQd8iKwSMHWjl/O817G3uBnIFNjnQJuesI68u4OTLiBFdcbYEdFCoEOfaS35inz1");
    }

    #[test]
    fn sha256_full_setting_drepper() {
        let out = crypt_hash(b"Hello world!", b"$5$saltstring").unwrap();
        assert_eq!(out, "$5$saltstring$5B8vYYiY.CVt1RlTTf8KbXBH3hsxY/GNooZaBBGWEc5");
    }

    #[test]
    fn rounds_explicit_roundtrips_in_output() {
        let out = crypt_hash(b"Hello world!", b"$5$rounds=10000$saltstringsaltstring").unwrap();
        // salt truncated to 16, rounds preserved in the prefix
        assert_eq!(out, "$5$rounds=10000$saltstringsaltst$3xv.VbSHBb41AL9AvLeujZkZRBAwqFMz2.opqey6IcA");
    }

    #[test]
    fn full_hash_is_a_valid_setting_for_reverify() {
        // The full hash string is itself a valid setting (salt parse stops at
        // '$'), so re-crypting the same key reproduces it.
        let first = crypt_hash(b"swordfish", b"$6$abcdefgh").unwrap();
        let again = crypt_hash(b"swordfish", first.as_bytes()).unwrap();
        assert_eq!(first, again);
    }

    #[test]
    fn rejects_unsupported() {
        assert!(crypt_hash(b"x", b"$1$salt").is_none()); // md5crypt unsupported
        assert!(crypt_hash(b"x", b"plain").is_none());
        assert!(crypt_hash(b"x", b"$6").is_none());
    }
}
