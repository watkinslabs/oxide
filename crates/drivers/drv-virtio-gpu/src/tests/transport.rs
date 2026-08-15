use crate::*;

#[test]
fn gpu_profile_binds_ctrlq_irq_to_its_exact_child_key() {
    let key = virtio::VirtioChildDeviceKey::from_raw(0x13);
    let profile = transport_profile_for(key);
    let q0 = profile.q0_handler.expect("ctrlq handler");
    assert!(matches!(q0, virtio::VirtioQueueIrq::Context { arg, .. } if arg == key.raw() as usize));
    let q1 = profile.queue_plans[1].and_then(|plan| plan.msix_handler).expect("cursorq handler");
    assert!(matches!(q1, virtio::VirtioQueueIrq::Context { arg, .. } if arg == key.raw() as usize));
}
