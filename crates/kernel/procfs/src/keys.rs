// `/proc/keys` + `/proc/key-users` (Linux `security/keys/proc.c`).
//
// Both are generator files, not snapshots. `/proc/keys` is rendered per read
// in the READING task's context because `proc_keys_show` omits every key that
// task cannot `KEY_NEED_VIEW`: a body captured once at registration and shared
// by every opener would hand one task's filtered view — including the serials
// of keys it may not touch — to every other task on the system.
#![cfg(any(target_os = "oxide-kernel", test))]

use vfs::InodeRef;

use crate::dyn_file::make_gen_file;
use crate::hooks::keyring;

/// `/proc/keys` — one line per key the reader may VIEW. # C: O(1)
pub fn make_proc_keys() -> InodeRef { make_gen_file(crate::ids::KEYS, keyring::keys) }

/// `/proc/key-users` — one line per uid holding a key charge. # C: O(1)
pub fn make_proc_key_users() -> InodeRef { make_gen_file(crate::ids::KEY_USERS, keyring::key_users) }

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::sync::Arc;
    use alloc::vec::Vec;
    use core::sync::atomic::{AtomicI64, AtomicU64, Ordering};
    use vfs::{Dentry, File, OpenFlags};
    use crate::proc_handler::{IntHook, ProcHandler};

    /// A stand-in key store: the generation counter every fake render embeds,
    /// so a second read that returns the first read's bytes is detectable.
    static GENERATION: AtomicU64 = AtomicU64::new(0);
    /// The stand-in `key_quota_maxkeys` the sysctl leaf writes through to.
    static FAKE_MAXKEYS: AtomicI64 = AtomicI64::new(1);

    fn fake_keys() -> Vec<u8> {
        let n = GENERATION.fetch_add(1, Ordering::SeqCst);
        alloc::format!("{n:08x} I--Q--- 1 perm 3f010000 0 0 keyring _ses: empty\n").into_bytes()
    }
    fn fake_key_users() -> Vec<u8> { b"    0:     1 1/1 1/200 20/20000\n".to_vec() }
    fn fake_maxkeys() -> i64 { FAKE_MAXKEYS.load(Ordering::SeqCst) }
    fn set_fake_maxkeys(v: i64) { FAKE_MAXKEYS.store(v, Ordering::SeqCst) }

    fn body(inode: &InodeRef) -> Vec<u8> {
        let f = File::new(Arc::clone(inode), Dentry::new_root(Arc::clone(inode)), OpenFlags::O_RDONLY);
        f.open_hook().unwrap();
        let mut buf = [0u8; 256];
        let n = f.read(&mut buf).unwrap();
        buf[..n].to_vec()
    }

    // The file must render on EVERY read: its content is filtered by the
    // reading task's view permission, so a cached body leaks one task's view.
    #[test]
    fn proc_keys_renders_per_read_through_the_installed_hook() {
        keyring::set_report_hooks(fake_keys, fake_key_users);
        let inode = make_proc_keys();
        let first = body(&inode);
        let second = body(&inode);
        assert!(first.ends_with(b"keyring _ses: empty\n"), "{first:?}");
        assert_ne!(first, second, "each read re-renders in its own reader's context");
    }

    #[test]
    fn proc_key_users_renders_the_charge_table() {
        keyring::set_report_hooks(fake_keys, fake_key_users);
        assert_eq!(body(&make_proc_key_users()), fake_key_users());
    }

    // A write to the sysctl leaf must reach the store's ceiling, not a
    // procfs-local cell: a knob that reads back but gates nothing is a lie
    // told to every hardening script that sets it.
    #[test]
    fn keys_sysctl_write_reaches_the_bound_ceiling() {
        keyring::set_quota_hooks((fake_maxkeys, set_fake_maxkeys), (fake_maxkeys, set_fake_maxkeys),
            (fake_maxkeys, set_fake_maxkeys), (fake_maxkeys, set_fake_maxkeys));
        let leaf = IntHook { get: keyring::maxkeys, set: keyring::set_maxkeys,
            bounds: Some(keyring::KEY_QUOTA_BOUNDS) };
        leaf.store(b"777\n").expect("an in-range ceiling is accepted");
        assert_eq!(FAKE_MAXKEYS.load(Ordering::SeqCst), 777);
        assert_eq!(leaf.format(), b"777\n".to_vec(), "the read reflects the live ceiling");
        // `security/keys/sysctl.c` registers extra1 = 1: a zero ceiling is out
        // of range and must not reach the store.
        assert!(leaf.store(b"0\n").is_err());
        assert_eq!(FAKE_MAXKEYS.load(Ordering::SeqCst), 777);
    }
}
