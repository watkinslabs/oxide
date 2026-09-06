use alloc::string::String;
use core::sync::atomic::{AtomicBool, Ordering};

use crate::dentry::Dentry;
use crate::inode::InodeRef;

static INSTANTIATE_CALLBACK_SAW_UNLOCKED_REGISTRY: AtomicBool = AtomicBool::new(false);
static ANON_CALLBACK_SAW_UNLOCKED_REGISTRY: AtomicBool = AtomicBool::new(false);

struct InstantiateHookRestore(Option<super::permission::InodeInstantiateHook>);

impl Drop for InstantiateHookRestore {
    fn drop(&mut self) {
        *super::permission::INODE_INSTANTIATE_HOOK.lock() = self.0;
    }
}

struct AnonHookRestore(Option<super::permission::InodeInitSecurityAnonHook>);

impl Drop for AnonHookRestore {
    fn drop(&mut self) {
        *super::permission::INODE_INIT_SECURITY_ANON_HOOK.lock() = self.0;
    }
}

fn probe_instantiate_hook_registry(_: &Dentry, _: &InodeRef) {
    INSTANTIATE_CALLBACK_SAW_UNLOCKED_REGISTRY.store(
        super::permission::INODE_INSTANTIATE_HOOK.try_lock().is_some(),
        Ordering::Release,
    );
}

fn probe_anon_hook_registry(
    _: &InodeRef,
    _: &str,
    _: Option<&InodeRef>,
) -> crate::KResult<()> {
    ANON_CALLBACK_SAW_UNLOCKED_REGISTRY.store(
        super::permission::INODE_INIT_SECURITY_ANON_HOOK.try_lock().is_some(),
        Ordering::Release,
    );
    Ok(())
}

#[test]
fn d_instantiate_releases_hook_registry_before_callback() {
    INSTANTIATE_CALLBACK_SAW_UNLOCKED_REGISTRY.store(false, Ordering::Release);
    let old = *super::permission::INODE_INSTANTIATE_HOOK.lock();
    let restore = InstantiateHookRestore(old);
    super::permission::set_inode_instantiated_hook(probe_instantiate_hook_registry);

    let dentry = Dentry::new_negative(None, String::from("instantiate-probe"));
    let inode = crate::make_static_file_inode(b"instantiate-probe");
    crate::dcache::d_instantiate(&dentry, inode);
    drop(restore);

    assert!(
        INSTANTIATE_CALLBACK_SAW_UNLOCKED_REGISTRY.load(Ordering::Acquire),
        "instantiate callback ran while the hook registry spinlock was held",
    );
}

#[test]
fn anonymous_security_releases_hook_registry_before_callback() {
    ANON_CALLBACK_SAW_UNLOCKED_REGISTRY.store(false, Ordering::Release);
    let old = *super::permission::INODE_INIT_SECURITY_ANON_HOOK.lock();
    let restore = AnonHookRestore(old);
    super::permission::set_inode_init_security_anon_hook(probe_anon_hook_registry);

    let inode = crate::make_static_file_inode(b"anon-security-probe");
    assert!(super::permission::inode_init_security_anon(&inode, "anon", None).is_ok());
    drop(restore);
    assert!(
        ANON_CALLBACK_SAW_UNLOCKED_REGISTRY.load(Ordering::Acquire),
        "anonymous-security callback ran while the hook registry spinlock was held",
    );
}
