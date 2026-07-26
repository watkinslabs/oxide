//! crypt — glibc-ABI password hashing (docs/59§6 G17a). $5$ (sha256crypt),
//! $6$ (sha512crypt) per Drepper 2007, and $y$ (yescrypt, scrypt+pwxform);
//! the hash cores live in the workspace `crypt` crate (aliased `libcrypt`).
//! Pure `crypt_hash` assembles the full setting+digest string; crypt/crypt_r
//! are the C ABI. $y$'s field grammar differs from $5$/$6$'s
//! `[rounds=N$]salt` shape, so it is parsed/assembled entirely inside
//! `libcrypt::yescrypt` and dispatched here before the shared `Setting` path.
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
    if setting.starts_with(b"$y$") { return libcrypt::yescrypt::hash(key, setting); }
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

// crypt base64 alphabet (itoa64) — distinct from standard base64.
const ITOA64: &[u8; 64] = b"./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

/// # C: crypt_gensalt setting body for `$5$`/`$6$`/`$y$`.
/// "$id$[rounds=N$]<salt>"; salt = crypt-b64 of min(4, rbytes/3) little-endian
/// 3-byte groups (≤16 chars). rounds= emitted only when ≠ default. None on an
/// unsupported prefix or fewer than 3 rbytes. `$y$`'s shape (flavor/N/r
/// fields + a variable-length salt, `count` a 1..=11 cost factor rather than
/// a rounds count) is generated entirely by `libcrypt::yescrypt::gensalt`.
pub(crate) fn gensalt(prefix: &[u8], count: u32, rbytes: &[u8]) -> Option<String> {
    if prefix.starts_with(b"$y$") { return libcrypt::yescrypt::gensalt(count, rbytes); }
    let id = if prefix.starts_with(b"$5$") { b'5' } else if prefix.starts_with(b"$6$") { b'6' } else { return None };
    let groups = (rbytes.len() / 3).min(4);
    if groups == 0 { return None; }
    let mut out = String::new();
    out.push('$'); out.push(id as char); out.push('$');
    if count != 0 {
        let r = count.clamp(ROUNDS_MIN, ROUNDS_MAX);
        if r != ROUNDS_DEFAULT { out.push_str("rounds="); push_u32(&mut out, r); out.push('$'); }
    }
    for g in 0..groups {
        let v = rbytes[g * 3] as u32 | ((rbytes[g * 3 + 1] as u32) << 8) | ((rbytes[g * 3 + 2] as u32) << 16);
        out.push(ITOA64[(v & 0x3f) as usize] as char);
        out.push(ITOA64[((v >> 6) & 0x3f) as usize] as char);
        out.push(ITOA64[((v >> 12) & 0x3f) as usize] as char);
        out.push(ITOA64[((v >> 18) & 0x3f) as usize] as char);
    }
    Some(out)
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

    // # C: char *fcrypt(const char *key, const char *setting)
    #[no_mangle]
    pub unsafe extern "C" fn fcrypt(key: *const u8, setting: *const u8) -> *mut u8 {
        // SAFETY: legacy libcrypt alias of crypt; same C-string contract.
        unsafe { crypt(key, setting) }
    }

    // # C: char *xcrypt(const char *key, const char *setting)
    #[no_mangle]
    pub unsafe extern "C" fn xcrypt(key: *const u8, setting: *const u8) -> *mut u8 {
        // SAFETY: libxcrypt compatibility alias of crypt.
        unsafe { crypt(key, setting) }
    }

    // # C: char *xcrypt_r(const char *key, const char *setting, struct crypt_data *data)
    #[no_mangle]
    pub unsafe extern "C" fn xcrypt_r(key: *const u8, setting: *const u8, data: *mut u8) -> *mut u8 {
        // SAFETY: libxcrypt compatibility alias of crypt_r.
        unsafe { crypt_r(key, setting, data) }
    }

    const ERANGE: i32 = 34;
    const ENOMEM: i32 = 12;
    static GSOUT: OutBuf = OutBuf(UnsafeCell::new([0; OUTLEN]));

    // rbytes window: borrow the caller's bytes, or (NULL) fill `scratch` from
    // getrandom for a random salt. None ⇒ insufficient entropy.
    unsafe fn rbytes_window<'a>(rbytes: *const u8, nrbytes: i32, scratch: &'a mut [u8; 16]) -> Option<&'a [u8]> {
        // SAFETY: rbytes is null or points at nrbytes readable bytes.
        unsafe {
            if rbytes.is_null() {
                let n = crate::posix::random::getrandom(scratch.as_mut_ptr(), 16, 0);
                if n < 16 { return None; }
                Some(&scratch[..])
            } else if nrbytes <= 0 { None }
            else { Some(core::slice::from_raw_parts(rbytes, nrbytes as usize)) }
        }
    }

    // # C: char *crypt_gensalt(const char *prefix, unsigned long count, const char *rbytes, int nrbytes)
    #[no_mangle]
    pub unsafe extern "C" fn crypt_gensalt(prefix: *const u8, count: u64, rbytes: *const u8, nrbytes: i32) -> *mut u8 {
        // SAFETY: prefix is a C string; rbytes is null or nrbytes bytes; result in
        // the process-global GSOUT buffer (separate from crypt's OUT).
        unsafe {
            let mut sc = [0u8; 16];
            let rb = match rbytes_window(rbytes, nrbytes, &mut sc) { Some(r) => r, None => { errno::set(EINVAL); return core::ptr::null_mut() } };
            match gensalt(as_bytes(prefix), count as u32, rb) {
                Some(s) => store(GSOUT.0.get() as *mut u8, &s),
                None => { errno::set(EINVAL); core::ptr::null_mut() }
            }
        }
    }

    // # C: char *xcrypt_gensalt(const char *prefix, unsigned long count, const char *rbytes, int nrbytes)
    #[no_mangle]
    pub unsafe extern "C" fn xcrypt_gensalt(prefix: *const u8, count: u64, rbytes: *const u8, nrbytes: i32) -> *mut u8 {
        // SAFETY: libxcrypt compatibility alias of crypt_gensalt.
        unsafe { crypt_gensalt(prefix, count, rbytes, nrbytes) }
    }

    // # C: char *crypt_gensalt_rn(const char *prefix, unsigned long count, const char *rbytes, int nrbytes, char *output, int output_size)
    #[no_mangle]
    pub unsafe extern "C" fn crypt_gensalt_rn(prefix: *const u8, count: u64, rbytes: *const u8, nrbytes: i32, output: *mut u8, output_size: i32) -> *mut u8 {
        // SAFETY: output is a caller buffer of output_size bytes; result written
        // there iff it fits (ERANGE otherwise).
        unsafe {
            let mut sc = [0u8; 16];
            let rb = match rbytes_window(rbytes, nrbytes, &mut sc) { Some(r) => r, None => { errno::set(EINVAL); return core::ptr::null_mut() } };
            match gensalt(as_bytes(prefix), count as u32, rb) {
                Some(s) => { if s.len() + 1 > output_size as usize { errno::set(ERANGE); return core::ptr::null_mut(); } store(output, &s) }
                None => { errno::set(EINVAL); core::ptr::null_mut() }
            }
        }
    }

    // # C: char *crypt_gensalt_r(const char *prefix, unsigned long count, const char *rbytes, int nrbytes, char *output, int output_size)
    #[no_mangle]
    pub unsafe extern "C" fn crypt_gensalt_r(prefix: *const u8, count: u64, rbytes: *const u8, nrbytes: i32, output: *mut u8, output_size: i32) -> *mut u8 {
        // SAFETY: historical alias of crypt_gensalt_rn; same output buffer contract.
        unsafe { crypt_gensalt_rn(prefix, count, rbytes, nrbytes, output, output_size) }
    }

    // # C: char *xcrypt_gensalt_r(const char *prefix, unsigned long count, const char *rbytes, int nrbytes, char *output, int output_size)
    #[no_mangle]
    pub unsafe extern "C" fn xcrypt_gensalt_r(prefix: *const u8, count: u64, rbytes: *const u8, nrbytes: i32, output: *mut u8, output_size: i32) -> *mut u8 {
        // SAFETY: libxcrypt compatibility alias of crypt_gensalt_rn.
        unsafe { crypt_gensalt_rn(prefix, count, rbytes, nrbytes, output, output_size) }
    }

    // # C: char *crypt_gensalt_ra(const char *prefix, unsigned long count, const char *rbytes, int nrbytes)
    #[no_mangle]
    pub unsafe extern "C" fn crypt_gensalt_ra(prefix: *const u8, count: u64, rbytes: *const u8, nrbytes: i32) -> *mut u8 {
        // SAFETY: result is heap-allocated for the caller to free (libxcrypt _ra).
        unsafe {
            let mut sc = [0u8; 16];
            let rb = match rbytes_window(rbytes, nrbytes, &mut sc) { Some(r) => r, None => { errno::set(EINVAL); return core::ptr::null_mut() } };
            match gensalt(as_bytes(prefix), count as u32, rb) {
                Some(s) => { let p = crate::malloc::heap::malloc(s.len() + 1); if p.is_null() { errno::set(ENOMEM); return core::ptr::null_mut(); } store(p, &s) }
                None => { errno::set(EINVAL); core::ptr::null_mut() }
            }
        }
    }

    // # C: char *crypt_rn(const char *phrase, const char *setting, void *data, int size)
    #[no_mangle]
    pub unsafe extern "C" fn crypt_rn(phrase: *const u8, setting: *const u8, data: *mut u8, size: i32) -> *mut u8 {
        // SAFETY: data is a caller buffer of `size` bytes; result iff it fits.
        unsafe {
            match crypt_hash(as_bytes(phrase), as_bytes(setting)) {
                Some(s) => { if s.len() + 1 > size as usize { errno::set(ERANGE); return core::ptr::null_mut(); } store(data, &s) }
                None => { errno::set(EINVAL); core::ptr::null_mut() }
            }
        }
    }

    // # C: char *crypt_ra(const char *phrase, const char *setting, void **data, int *size)
    #[no_mangle]
    pub unsafe extern "C" fn crypt_ra(phrase: *const u8, setting: *const u8, data: *mut *mut u8, size: *mut i32) -> *mut u8 {
        // SAFETY: *data is null or a heap block of *size bytes; (re)allocated to
        // fit the result, with *data/*size updated.
        unsafe {
            match crypt_hash(as_bytes(phrase), as_bytes(setting)) {
                Some(s) => {
                    let need = s.len() + 1;
                    if (*data).is_null() || (*size as usize) < need {
                        let np = crate::malloc::heap::realloc(*data, need);
                        if np.is_null() { errno::set(ENOMEM); return core::ptr::null_mut(); }
                        *data = np; *size = need as i32;
                    }
                    store(*data, &s)
                }
                None => { errno::set(EINVAL); core::ptr::null_mut() }
            }
        }
    }

    // # C: int crypt_checksalt(const char *setting)
    #[no_mangle]
    pub unsafe extern "C" fn crypt_checksalt(setting: *const u8) -> i32 {
        // SAFETY: setting is null or a NUL-terminated C string. Return
        // libxcrypt's stable public status constants for the supported surface.
        unsafe {
            let s = as_bytes(setting);
            if s.is_empty() { return 1; } // CRYPT_SALT_INVALID
            let ok = if s.starts_with(b"$y$") { libcrypt::yescrypt::setting_supported(s) } else { parse_setting(s).is_some() };
            if ok { 0 } else { 3 } // OK, else LEGACY/unsupported
        }
    }

    // # C: const char *crypt_preferred_method(void) — yescrypt ($y$) is our
    // strongest supported method (matches libxcrypt's own default).
    #[no_mangle]
    pub extern "C" fn crypt_preferred_method() -> *const u8 {
        b"$y$\0".as_ptr()
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

    // Vectors captured from host libxcrypt crypt_gensalt (rbytes = i*17, i=0..16).
    #[test]
    fn gensalt_vectors_match_libxcrypt() {
        let rb: [u8; 16] = core::array::from_fn(|i| (i * 17) as u8);
        assert_eq!(gensalt(b"$6$", 0, &rb).unwrap(), "$6$.2V6nEIJaR5WNeui");
        assert_eq!(gensalt(b"$5$", 5000, &rb).unwrap(), "$5$.2V6nEIJaR5WNeui");
        assert_eq!(gensalt(b"$6$", 1000, &rb).unwrap(), "$6$rounds=1000$.2V6nEIJaR5WNeui");
        assert_eq!(gensalt(b"$6$", 10000, &rb).unwrap(), "$6$rounds=10000$.2V6nEIJaR5WNeui");
        assert_eq!(gensalt(b"$6$", 100, &rb).unwrap(), "$6$rounds=1000$.2V6nEIJaR5WNeui");  // clamped
        assert_eq!(gensalt(b"$6$", 0, &rb[..8]).unwrap(), "$6$.2V6nEIJ");                    // 8 bytes ⇒ 8 chars
        assert!(gensalt(b"$1$", 0, &rb).is_none());   // unsupported method
        assert!(gensalt(b"$6$", 0, &rb[..2]).is_none()); // <3 rbytes
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

    // yescrypt ($y$) wiring — F723. Byte-for-byte vectors against the real
    // shadow hashes present in the image (docs/59§6 G17a); full oracle
    // coverage lives in libcrypt::yescrypt::tests (39 host-libxcrypt
    // vectors). This just confirms the glibc-level dispatch (crypt_hash /
    // gensalt) reaches yescrypt for `$y$` without disturbing $5$/$6$.
    #[test]
    fn yescrypt_dispatch_matches_real_shadow_hashes() {
        let out = crypt_hash(b"oxide", b"$y$j9T$7nufRRDsGwv3J9mgBko4/1").unwrap();
        assert_eq!(out, "$y$j9T$7nufRRDsGwv3J9mgBko4/1$mMYAJuf8p8eR0l7UfW3zAuGX7ZtQL2e8sy0i7WtCbJB");

        // Wrong password against the same salt must not match.
        let wrong = crypt_hash(b"not-the-password", b"$y$j9T$7nufRRDsGwv3J9mgBko4/1").unwrap();
        assert_ne!(wrong, out);
    }

    #[test]
    fn yescrypt_gensalt_dispatch() {
        let rb: [u8; 16] = core::array::from_fn(|i| (i * 17) as u8);
        let setting = gensalt(b"$y$", 1, &rb).unwrap();
        assert!(setting.starts_with("$y$"));
        let h1 = crypt_hash(b"pw", setting.as_bytes()).unwrap();
        let h2 = crypt_hash(b"pw", h1.as_bytes()).unwrap(); // full hash re-verifies
        assert_eq!(h1, h2);
    }

    #[test]
    fn sha5xx_unchanged_alongside_yescrypt_dispatch() {
        // Task requirement: $5$/$6$ still work unchanged now that `$y$` has
        // its own early-return branch in crypt_hash.
        assert_eq!(
            crypt_hash(b"Hello world!", b"$6$saltstring").unwrap(),
            "$6$saltstring$svn8UoSVapNtMuq1ukKS4tPQd8iKwSMHWjl/O817G3uBnIFNjnQJuesI68u4OTLiBFdcbYEdFCoEOfaS35inz1"
        );
        assert_eq!(
            crypt_hash(b"Hello world!", b"$5$saltstring").unwrap(),
            "$5$saltstring$5B8vYYiY.CVt1RlTTf8KbXBH3hsxY/GNooZaBBGWEc5"
        );
    }
}
