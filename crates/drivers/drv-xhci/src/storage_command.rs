use super::*;

fn storage_complete(irq: Binding, trb_pa: u64, slot: u8, endpoint: u8, length: u32, timeout_ns: u64) -> bool {
    let endpoint_id = (endpoint & 0x0f).checked_mul(2).and_then(|id| id.checked_add(u8::from(endpoint & 0x80 != 0)));
    let Some(completion) = irq.wait_transfer_completion(trb_pa, timeout_ns) else { return false; };
    completion.completion_code == crate::ring::COMPLETION_SUCCESS && completion.slot == slot
        && Some(completion.endpoint_id) == endpoint_id && completion.residual <= length
}

fn storage_remaining(deadline_ns: u64) -> Option<u64> {
    let remaining = deadline_ns.saturating_sub(sched::deadline::clock::now_ns());
    (remaining != 0).then_some(remaining)
}

/// Completed Bulk-Only command facts.  A Failed CSW is a completed SCSI
/// command whose sense must be fetched, not a transport-layer timeout.
pub(crate) struct StorageCommandResult {
    pub(crate) data: Vec<u8>,
    pub(crate) status: crate::storage::CswStatus,
    pub(crate) residue: u32,
}

pub(crate) fn storage_command(device: &UsbDevice, tag: u32, lun: scsi::Lun, cdb: &[u8], data_bytes: u32,
                              device_to_host: bool, out: Option<&[u8]>, timeout_ms: u32) -> Option<StorageCommandResult> {
    let _transaction = device.lock_transfer();
    let deadline_ns = sched::deadline::clock::now_ns().saturating_add(u64::from(timeout_ms).saturating_mul(1_000_000));
    let lun = u8::try_from(lun.value()).ok().filter(|lun| *lun <= crate::storage::USB_BULK_MAX_LUN)?;
    if device_to_host != out.is_none() || out.is_some_and(|bytes| bytes.len() != data_bytes as usize) { return None; }
    let Some(Some((irq, slot, storage, cbw))) = device.with_transport(|mmio, irq, _, state| {
        let storage = state.device.storage_interface()?;
        if let Some(bytes) = out { if !state.device.set_storage_data(bytes) { return None; } }
        let slot = state.slot;
        let cbw = state.device.submit_storage_cbw(mmio, slot, tag, data_bytes, device_to_host, lun, cdb)?;
        Some((irq, slot, storage, cbw))
    }) else { return None; };
    if !storage_complete(irq, cbw, slot, storage.bulk_out, crate::storage::CBW_BYTES as u32, storage_remaining(deadline_ns)?) { return None; }
    if data_bytes != 0 {
        let Some(Some(data)) = device.with_transport(|mmio, irq, _, state| {
            let storage = state.device.storage_interface()?;
            let slot = state.slot;
            let trb = state.device.submit_storage_data(mmio, slot, data_bytes, device_to_host)?;
            Some((irq, slot, storage, trb))
        }) else { return None; };
        let endpoint = if device_to_host { data.2.bulk_in } else { data.2.bulk_out };
        if !storage_complete(data.0, data.3, data.1, endpoint, data_bytes, storage_remaining(deadline_ns)?) { return None; }
    }
    let Some(Some((irq, slot, storage, csw))) = device.with_transport(|mmio, irq, _, state| {
        let storage = state.device.storage_interface()?;
        let slot = state.slot;
        let trb = state.device.submit_storage_csw(mmio, slot)?;
        Some((irq, slot, storage, trb))
    }) else { return None; };
    if !storage_complete(irq, csw, slot, storage.bulk_in, crate::storage::CSW_BYTES as u32, storage_remaining(deadline_ns)?) { return None; }
    let Some(result) = device.with_transport(|_, _, _, state| {
        let (status, residue) = state.device.storage_csw(tag, data_bytes)?;
        let data = if device_to_host { state.device.storage_data(data_bytes as usize)? } else { Vec::new() };
        Some(StorageCommandResult { data, status, residue })
    }) else { return None; };
    result
}
