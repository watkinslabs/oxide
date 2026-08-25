use super::*;

#[cfg(feature = "debug-hibernate")]
/// # C: O(1)
pub fn cpu_off(cpu: u32, phase: CpuOffPhase, result: CpuOffResult) {
    klog::write_raw(b"[hibernate] cpu_off="); klog::write_dec_u64(cpu as u64);
    klog::write_raw(b" phase=");
    klog::write_raw(match phase {
        CpuOffPhase::Request => b"request", CpuOffPhase::Callfn => b"callfn",
        CpuOffPhase::OfflineResult => b"offline_result",
        CpuOffPhase::ConfirmDead => b"confirm_dead", CpuOffPhase::Unwind => b"unwind",
    });
    klog::write_raw(b" result=");
    klog::write_raw(match result {
        CpuOffResult::Begin => b"begin", CpuOffResult::Ok => b"ok",
        CpuOffResult::Refused => b"refused", CpuOffResult::Timeout => b"timeout",
    });
    klog::write_raw(b"\n");
}

#[cfg(not(feature = "debug-hibernate"))]
#[inline(always)]
/// # C: O(1)
pub fn cpu_off(_: u32, _: CpuOffPhase, _: CpuOffResult) {}

#[cfg(feature = "debug-hibernate")]
/// # C: O(1)
pub fn cpu_off_callfn(cpu: u32, curr_idle: bool, nr_running: u32,
    wake_pending: bool, wake_count: u64, softirq_pending: u32)
{
    klog::write_raw(b"[hibernate] cpu_off="); klog::write_dec_u64(cpu as u64);
    klog::write_raw(b" phase=callfn curr_idle="); klog::write_dec_u64(curr_idle as u64);
    klog::write_raw(b" nr_running="); klog::write_dec_u64(nr_running as u64);
    klog::write_raw(b" wake_pending="); klog::write_dec_u64(wake_pending as u64);
    klog::write_raw(b" wake_count="); klog::write_dec_u64(wake_count);
    klog::write_raw(b" softirq_pending="); klog::write_hex_u64(softirq_pending as u64);
    klog::write_raw(b"\n");
}

#[cfg(not(feature = "debug-hibernate"))]
#[inline(always)]
/// # C: O(1)
pub fn cpu_off_callfn(_: u32, _: bool, _: u32, _: bool, _: u64, _: u32) {}

#[cfg(feature = "debug-hibernate")]
/// # C: O(1)
pub fn cpu_off_transport(sender: u32, target: u32, state: CpuCallTransport) {
    klog::write_raw(b"[hibernate] cpu_off_transport sender=");
    klog::write_dec_u64(sender as u64);
    klog::write_raw(b" target="); klog::write_dec_u64(target as u64);
    klog::write_raw(b" state=");
    klog::write_raw(match state {
        CpuCallTransport::SameCpu => b"same_cpu", CpuCallTransport::Offline => b"offline",
        CpuCallTransport::Queued => b"queued", CpuCallTransport::NoHardware => b"no_hardware",
        CpuCallTransport::IcrRefused => b"icr_refused",
        CpuCallTransport::IcrSent => b"icr_sent",
    });
    klog::write_raw(b"\n");
}

#[cfg(not(feature = "debug-hibernate"))]
#[inline(always)]
/// # C: O(1)
pub fn cpu_off_transport(_: u32, _: u32, _: CpuCallTransport) {}

#[cfg(feature = "debug-hibernate")]
/// # C: O(1)
pub fn cpu_off_transport_facts(sender: u32, target: u32, online: bool,
    hardware_id: Option<u64>)
{
    klog::write_raw(b"[hibernate] cpu_off_transport sender=");
    klog::write_dec_u64(sender as u64);
    klog::write_raw(b" target="); klog::write_dec_u64(target as u64);
    klog::write_raw(b" online="); klog::write_dec_u64(online as u64);
    klog::write_raw(b" hardware_id=");
    match hardware_id {
        Some(id) => klog::write_hex_u64(id), None => klog::write_raw(b"none"),
    }
    klog::write_raw(b"\n");
}

#[cfg(not(feature = "debug-hibernate"))]
#[inline(always)]
/// # C: O(1)
pub fn cpu_off_transport_facts(_: u32, _: u32, _: bool, _: Option<u64>) {}
