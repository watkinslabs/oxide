// Every parameter here is read only from inside `debug_boot!`, which expands
// to nothing unless the `debug-boot` feature is on — hence the `_` prefixes.

pub(super) fn binding(_bdf: pci::Bdf, _queue_vector: u16, _entry_va: u64, _msg_addr: u64, _msg_data: u32) {
    debug_boot! {
        // SAFETY: entry_va addresses the MSI-X table entry just written by
        // this transport binding and remains mapped for the transport record.
        let (addr_lo, addr_hi, data, ctrl) = unsafe {
            (
                core::ptr::read_volatile(_entry_va as *const u32),
                core::ptr::read_volatile((_entry_va + 4) as *const u32),
                core::ptr::read_volatile((_entry_va + 8) as *const u32),
                core::ptr::read_volatile((_entry_va + pci::MSIX_VECTOR_CONTROL_OFF) as *const u32),
            )
        };
        klog::write_raw(b"[INFO]  msix-bind ");
        klog::write_dec_u64(_bdf.bus as u64);
        klog::write_raw(b":");
        klog::write_dec_u64(_bdf.device as u64);
        klog::write_raw(b".");
        klog::write_dec_u64(_bdf.function as u64);
        klog::write_raw(b" vec=");
        klog::write_dec_u64(_queue_vector as u64);
        klog::write_raw(b" msg_addr=");
        klog::write_hex_u64(_msg_addr);
        klog::write_raw(b" msg_data=");
        klog::write_hex_u64(_msg_data as u64);
        klog::write_raw(b" rd_addr=");
        klog::write_hex_u64(((addr_hi as u64) << 32) | addr_lo as u64);
        klog::write_raw(b" rd_data=");
        klog::write_hex_u64(data as u64);
        klog::write_raw(b" ctrl=");
        klog::write_hex_u64(ctrl as u64);
        klog::write_raw(b"\n");
    }
}

#[cfg(target_arch = "aarch64")]
pub(super) fn its_alloc(
    _bdf: pci::Bdf,
    _rid: u32,
    _device_id: u32,
    _event_id: u32,
    _lpi: u32,
    _msg_addr: u64,
) {
    debug_boot! {
        klog::write_raw(b"[INFO]  its-msi ");
        klog::write_dec_u64(_bdf.bus as u64);
        klog::write_raw(b":");
        klog::write_dec_u64(_bdf.device as u64);
        klog::write_raw(b".");
        klog::write_dec_u64(_bdf.function as u64);
        klog::write_raw(b" rid=");
        klog::write_hex_u64(_rid as u64);
        klog::write_raw(b" did=");
        klog::write_hex_u64(_device_id as u64);
        klog::write_raw(b" event=");
        klog::write_hex_u64(_event_id as u64);
        klog::write_raw(b" lpi=");
        klog::write_dec_u64(_lpi as u64);
        klog::write_raw(b" msg_addr=");
        klog::write_hex_u64(_msg_addr);
        klog::write_raw(b"\n");
    }
}
