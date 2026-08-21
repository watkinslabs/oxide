use crate::hibernate::format::Header;
use crate::hibernate::restore::Compatibility;

#[cfg(feature = "debug-hibernate")]
fn word(bytes: &[u8; 32]) -> u64 { u64::from_le_bytes(bytes[..8].try_into().unwrap()) }

/// Emit the exact persistent/current identity boundary before admission.
/// # C: O(1)
#[cfg(feature = "debug-hibernate")]
pub fn compatibility(header: &Header, current: &Compatibility, writer: bool) {
    let mut mismatch = 0u64;
    mismatch |= u64::from(header.arch != current.arch) << 0;
    mismatch |= u64::from(header.cpu_count != current.cpu_count) << 1;
    mismatch |= u64::from(header.hardware_sig != current.hardware_sig) << 2;
    mismatch |= u64::from(header.build_id != current.build_id) << 3;
    mismatch |= u64::from(header.topology_id != current.topology_id) << 4;
    mismatch |= u64::from(header.cpu_id != current.cpu_id) << 5;
    klog::write_primary_raw(b"[hibernate] compatibility side=");
    klog::write_primary_raw(if writer { b"writer" } else { b"reader" });
    klog::write_primary_raw(b" mismatch="); klog::write_primary_hex_u64(mismatch);
    klog::write_primary_raw(b" arch="); klog::write_primary_dec_u64(current.arch as u64);
    klog::write_primary_raw(b" cpus="); klog::write_primary_dec_u64(current.cpu_count as u64);
    klog::write_primary_raw(b" hardware="); klog::write_primary_hex_u64(current.hardware_sig as u64);
    klog::write_primary_raw(b" build="); klog::write_primary_hex_u64(word(&current.build_id));
    klog::write_primary_raw(b" topology="); klog::write_primary_hex_u64(word(&current.topology_id));
    klog::write_primary_raw(b" cpu="); klog::write_primary_hex_u64(word(&current.cpu_id));
    klog::write_primary_raw(b"\n");
}

#[cfg(not(feature = "debug-hibernate"))]
#[inline(always)]
/// # C: O(1)
pub fn compatibility(_: &Header, _: &Compatibility, _: bool) {}
