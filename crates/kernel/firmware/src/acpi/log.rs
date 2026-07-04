#[cfg(feature = "debug-acpi")]
#[inline] pub(super) fn alog_raw(b: &[u8]) { klog::write_raw(b); }
#[cfg(not(feature = "debug-acpi"))]
#[inline] pub(super) fn alog_raw(_b: &[u8]) {}

#[cfg(feature = "debug-acpi")]
#[inline] pub(super) fn alog_dec(v: u64) { klog::write_dec_u64(v); }
#[cfg(not(feature = "debug-acpi"))]
#[inline] pub(super) fn alog_dec(_v: u64) {}

#[cfg(feature = "debug-acpi")]
#[inline] pub(super) fn alog_hex(v: u64) { klog::write_hex_u64(v); }
#[cfg(not(feature = "debug-acpi"))]
#[inline] pub(super) fn alog_hex(_v: u64) {}
