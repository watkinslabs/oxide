pub(super) fn binding(bdf: pci::Bdf, queue_vector: u16, entry_va: u64, msg_addr: u64, msg_data: u32) {
    debug_boot! {
        // SAFETY: entry_va addresses the MSI-X table entry just written by
        // this transport binding and remains mapped for the transport record.
        let (addr_lo, addr_hi, data, ctrl) = unsafe {
            (
                core::ptr::read_volatile(entry_va as *const u32),
                core::ptr::read_volatile((entry_va + 4) as *const u32),
                core::ptr::read_volatile((entry_va + 8) as *const u32),
                core::ptr::read_volatile((entry_va + pci::MSIX_VECTOR_CONTROL_OFF) as *const u32),
            )
        };
        klog::write_raw(b"[INFO]  msix-bind ");
        klog::write_dec_u64(bdf.bus as u64);
        klog::write_raw(b":");
        klog::write_dec_u64(bdf.device as u64);
        klog::write_raw(b".");
        klog::write_dec_u64(bdf.function as u64);
        klog::write_raw(b" vec=");
        klog::write_dec_u64(queue_vector as u64);
        klog::write_raw(b" msg_addr=");
        klog::write_hex_u64(msg_addr);
        klog::write_raw(b" msg_data=");
        klog::write_hex_u64(msg_data as u64);
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
    bdf: pci::Bdf,
    rid: u32,
    device_id: u32,
    event_id: u32,
    lpi: u32,
    msg_addr: u64,
) {
    debug_boot! {
        klog::write_raw(b"[INFO]  its-msi ");
        klog::write_dec_u64(bdf.bus as u64);
        klog::write_raw(b":");
        klog::write_dec_u64(bdf.device as u64);
        klog::write_raw(b".");
        klog::write_dec_u64(bdf.function as u64);
        klog::write_raw(b" rid=");
        klog::write_hex_u64(rid as u64);
        klog::write_raw(b" did=");
        klog::write_hex_u64(device_id as u64);
        klog::write_raw(b" event=");
        klog::write_hex_u64(event_id as u64);
        klog::write_raw(b" lpi=");
        klog::write_dec_u64(lpi as u64);
        klog::write_raw(b" msg_addr=");
        klog::write_hex_u64(msg_addr);
        klog::write_raw(b"\n");
    }
}
