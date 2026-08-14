// NVMe authentication KPI module manifest. `hmac` owns the Linux ABI context
// and hash transforms; `key` owns decoded DHCHAP secrets; `tls` owns PSK flows.

mod hmac;
mod kpp;
mod key;
mod keyring;
mod tls;

pub use hmac::{NVME_AUTH_DHGROUP_INVALID, NVME_AUTH_DHGROUP_NULL, NVME_AUTH_HASH_INVALID, NVME_AUTH_HASH_SHA256, NVME_AUTH_HASH_SHA384, NVME_AUTH_HASH_SHA512};

/// Register the complete in-kernel NVMe authentication surface.
/// # C: O(1)
pub fn export_symbols() {
    hmac::export_symbols();
    kpp::export_symbols();
    key::export_symbols();
    keyring::export_symbols();
    tls::export_symbols();
}

/// Install the canonical keyring implementation before native modules resolve it.
/// # C: O(1)
pub fn install_keyring_hooks(put: keyring::KeyPutHook, revoke: keyring::KeyRevokeHook,
    refresh: keyring::RefreshHook)
{
    keyring::install_hooks(put, revoke, refresh);
}
