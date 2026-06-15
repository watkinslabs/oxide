// sigset_t operations (docs/59§6 G9). glibc sigset_t is 128 bytes
// ([u64;16]); signal n lives in bit (n-1). The kernel only uses the low
// 64 bits, but the public type is the full 128 for ABI. Inner ops work on
// the word array (oracle-tested vs host sigemptyset/sigaddset/…).

pub const NSIG: i32 = 64;
const WORDS: usize = 16;

#[repr(C)]
pub struct sigset_t {
    pub __val: [u64; WORDS],
}
const _: () = assert!(core::mem::size_of::<sigset_t>() == 128);

// glibc reserves signals 32 and 33 (NPTL SIGCANCEL/SIGSETXID) and rejects
// them from the public sig{add,del,ismember}set with EINVAL.
fn valid(sig: i32) -> bool { sig >= 1 && sig as usize <= WORDS * 64 && sig != 32 && sig != 33 }

/// # C: zero a sigset
pub(crate) fn empty(s: &mut [u64; WORDS]) { *s = [0; WORDS]; }
/// # C: all-signals sigset
pub(crate) fn fill(s: &mut [u64; WORDS]) { *s = [!0u64; WORDS]; }
/// # C: set bit for `sig`; -1 if reserved/out of range
pub(crate) fn add(s: &mut [u64; WORDS], sig: i32) -> i32 {
    if !valid(sig) { return -1; }
    let n = (sig - 1) as usize;
    s[n / 64] |= 1u64 << (n % 64);
    0
}
/// # C: clear bit for `sig`; -1 if reserved/out of range
pub(crate) fn del(s: &mut [u64; WORDS], sig: i32) -> i32 {
    if !valid(sig) { return -1; }
    let n = (sig - 1) as usize;
    s[n / 64] &= !(1u64 << (n % 64));
    0
}
/// # C: 1 if `sig` is in the set, 0 if not, -1 if invalid
pub(crate) fn ismember(s: &[u64; WORDS], sig: i32) -> i32 {
    if !valid(sig) { return -1; }
    let n = (sig - 1) as usize;
    ((s[n / 64] >> (n % 64)) & 1) as i32
}

#[cfg(feature = "freestanding")]
mod exports {
    use super::*;
    // # C: int sigemptyset(sigset_t *set)
    #[no_mangle]
    pub unsafe extern "C" fn sigemptyset(set: *mut sigset_t) -> i32 {
        // SAFETY: set is a valid sigset_t out-param per the C contract.
        unsafe { empty(&mut (*set).__val); 0 }
    }
    // # C: int sigfillset(sigset_t *set)
    #[no_mangle]
    pub unsafe extern "C" fn sigfillset(set: *mut sigset_t) -> i32 {
        // SAFETY: set is a valid sigset_t out-param.
        unsafe { fill(&mut (*set).__val); 0 }
    }
    // # C: int sigaddset(sigset_t *set, int sig)
    #[no_mangle]
    pub unsafe extern "C" fn sigaddset(set: *mut sigset_t, sig: i32) -> i32 {
        // SAFETY: set is a valid sigset_t the caller owns.
        unsafe { add(&mut (*set).__val, sig) }
    }
    // # C: int sigdelset(sigset_t *set, int sig)
    #[no_mangle]
    pub unsafe extern "C" fn sigdelset(set: *mut sigset_t, sig: i32) -> i32 {
        // SAFETY: set is a valid sigset_t the caller owns.
        unsafe { del(&mut (*set).__val, sig) }
    }
    // # C: int sigismember(const sigset_t *set, int sig)
    #[no_mangle]
    pub unsafe extern "C" fn sigismember(set: *const sigset_t, sig: i32) -> i32 {
        // SAFETY: set is a valid sigset_t to read.
        unsafe { ismember(&(*set).__val, sig) }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn host_bytes(f: impl Fn(*mut libc::sigset_t)) -> [u8; 128] {
        // SAFETY: zeroed sigset is valid; f initialises it; we read its bytes.
        unsafe {
            let mut s: libc::sigset_t = core::mem::zeroed();
            f(&mut s);
            core::mem::transmute_copy(&s)
        }
    }
    fn our_bytes(v: &[u64; 16]) -> [u8; 128] {
        // SAFETY: [u64;16] and [u8;128] have identical size/layout.
        unsafe { core::mem::transmute_copy(v) }
    }
    #[test]
    fn empty_add_del_match_host() {
        let mut ours = [0u64; 16];
        empty(&mut ours);
        // SAFETY: libc::sigemptyset on a live set.
        assert_eq!(our_bytes(&ours), host_bytes(|s| unsafe { libc::sigemptyset(s); }));
        for sig in 1..=64 {
            add(&mut ours, sig);
            // SAFETY: libc set operations on a live, zero-initialised set.
            let h = host_bytes(|s| unsafe { libc::sigemptyset(s); for k in 1..=sig { libc::sigaddset(s, k); } });
            assert_eq!(our_bytes(&ours), h, "after add {sig}");
        }
        assert_eq!(ismember(&ours, 10), 1);
        assert_eq!(ismember(&ours, 32), -1); // reserved
        del(&mut ours, 10);
        assert_eq!(ismember(&ours, 10), 0);
    }
}
