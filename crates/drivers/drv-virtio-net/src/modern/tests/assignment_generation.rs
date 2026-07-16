use core::sync::atomic::Ordering;
use net::NetDev;

use super::super::rx::assignment::{completion, RxAssignments, INITIAL_GENERATION};
use super::{clear_test_state, ensure_net_runtime, first_iface_ip_for, install_rx_runtime,
    key, state, VirtioNetDev, MODERN_DEVS, TEST_STATE_LOCK};

fn retired_assignments() -> RxAssignments {
    let assignments = RxAssignments::new(1);
    assert_eq!(assignments.current(), INITIAL_GENERATION);
    assignments.retire();
    assignments
}

fn complete(assignments: &RxAssignments, expected_generation: u64) -> bool {
    let descriptor = assignments.descriptor(0).unwrap();
    let current_generation = assignments.current();
    let (deliver, repost_generation) = completion(
        descriptor.load(Ordering::Acquire), expected_generation, current_generation,
    );
    descriptor.store(repost_generation, Ordering::Release);
    deliver
}

#[test]
fn old_completion_is_dropped_after_retire() {
    let assignments = retired_assignments();
    let current = assignments.current();

    assert!(!complete(&assignments, current));
}

#[test]
fn stale_completion_repost_is_retagged() {
    let assignments = retired_assignments();
    let current = assignments.current();

    let _ = complete(&assignments, current);

    assert_eq!(
        assignments.descriptor(0).unwrap().load(Ordering::Acquire),
        current,
    );
}

#[test]
fn fresh_completion_is_delivered() {
    let assignments = retired_assignments();
    let current = assignments.current();

    assert!(!complete(&assignments, current));
    assert!(complete(&assignments, current));
}

#[test]
fn retirement_clears_namespace_arp_and_address_policy() {
    let _guard = TEST_STATE_LOCK.lock();
    clear_test_state();
    MODERN_DEVS.lock().extend([state(1), state(2)]);
    let dev1 = VirtioNetDev::new_for(key(1)).unwrap();
    let rt1 = ensure_net_runtime(key(1));
    let rt2 = ensure_net_runtime(key(2));
    let dst = net::Ipv4Addr::new(10, 0, 0, 2);
    rt1.arp.insert(dst, net::MacAddr([1; 6]));
    rt2.arp.insert(dst, net::MacAddr([2; 6]));
    let owner = dev1.clone() as alloc::sync::Arc<dyn net::NetDev>;
    install_rx_runtime(key(1), net::NetIfaceId::from_raw(11), owner,
        rt1.rx_assignments.current(), rt1.clone());
    assert!(super::super::set_softirq_ip_for_iface(
        net::NetIfaceId::from_raw(11), [10, 0, 0, 3],
    ));

    dev1.retire_namespace();

    assert_eq!(rt1.arp.lookup(dst), None);
    assert_eq!(rt2.arp.lookup(dst), Some(net::MacAddr([2; 6])));
    assert_eq!(first_iface_ip_for(key(1)), Some(net::Ipv4Addr::ANY));
    clear_test_state();
}

#[test]
fn ipv4_callback_updates_and_clears_device_runtime() {
    let _guard = TEST_STATE_LOCK.lock();
    clear_test_state();
    MODERN_DEVS.lock().push(state(3));
    let dev = VirtioNetDev::new_for(key(3)).unwrap();
    let runtime = ensure_net_runtime(key(3));
    let owner = dev.clone() as alloc::sync::Arc<dyn net::NetDev>;
    install_rx_runtime(key(3), net::NetIfaceId::from_raw(13), owner,
        runtime.rx_assignments.current(), runtime);

    dev.ipv4_addr_changed(Some(net::Ipv4Addr::new(192, 0, 2, 13)));
    assert_eq!(first_iface_ip_for(key(3)), Some(net::Ipv4Addr::new(192, 0, 2, 13)));
    dev.ipv4_addr_changed(None);
    assert_eq!(first_iface_ip_for(key(3)), Some(net::Ipv4Addr::ANY));
    clear_test_state();
}

#[test]
fn used_ring_drops_stale_completion_then_delivers_reposted_buffer() {
    const USED: usize = 0x100;
    const AVAIL: usize = 0x200;
    const NOTIFY: usize = 0x300;
    const BUFFER: usize = 0x400;
    const FRAME_TOTAL: u32 = 12 + 14;
    let _guard = TEST_STATE_LOCK.lock();
    clear_test_state();
    let mut memory = alloc::vec![0u8; 0x1000];
    let base = memory.as_mut_ptr() as u64;
    let mut device = state(7);
    device.hhdm = base;
    device.rxq.size = 2;
    device.rxq.desc_pa = 0x80;
    device.rxq.driver_pa = AVAIL as u64;
    device.rxq.device_pa = USED as u64;
    device.rxq.notify_va = base + NOTIFY as u64;
    device.rx_bufs[0].pa = BUFFER as u64;
    device.rx_bufs[0].len = 512;
    MODERN_DEVS.lock().push(device);
    let dev = VirtioNetDev::new_for(key(7)).unwrap();
    dev.retire_namespace();
    let runtime = ensure_net_runtime(key(7));
    let generation = runtime.rx_assignments.current();
    let owner = dev as alloc::sync::Arc<dyn net::NetDev>;
    install_rx_runtime(key(7), net::NetIfaceId::from_raw(17), owner.clone(), generation, runtime);
    memory[BUFFER] = 2;
    memory[BUFFER + 1] = 1;
    memory[BUFFER + 12..BUFFER + 26].fill(0x5a);
    memory[USED + 2..USED + 4].copy_from_slice(&1u16.to_le_bytes());
    memory[USED + 4..USED + 8].copy_from_slice(&0u32.to_le_bytes());
    memory[USED + 8..USED + 12].copy_from_slice(&FRAME_TOTAL.to_le_bytes());
    let mut delivered = 0;
    let mut delivered_metadata = None;

    assert_eq!(super::super::rx_poll_for(key(7), &owner, generation, |_, _| delivered += 1), 0);
    assert_eq!(delivered, 0);
    memory[USED + 2..USED + 4].copy_from_slice(&2u16.to_le_bytes());
    memory[USED + 12..USED + 16].copy_from_slice(&0u32.to_le_bytes());
    memory[USED + 16..USED + 20].copy_from_slice(&FRAME_TOTAL.to_le_bytes());
    assert_eq!(super::super::rx_poll_for(key(7), &owner, generation, |_, metadata| {
        delivered += 1;
        delivered_metadata = Some(metadata);
    }), 1);
    assert_eq!(delivered, 1);
    let metadata = delivered_metadata.unwrap();
    assert_eq!(metadata.checksum, net::PacketChecksum::Valid);
    assert_eq!(metadata.virtio.gso_type, 1);
    clear_test_state();
}

#[test]
fn stale_equal_generation_owner_cannot_consume_reprobe_ring() {
    const USED: usize = 0x100;
    const AVAIL: usize = 0x200;
    const NOTIFY: usize = 0x300;
    const BUFFER: usize = 0x400;
    const FRAME_TOTAL: u32 = 12 + 14;
    let _guard = TEST_STATE_LOCK.lock();
    clear_test_state();
    let mut memory = alloc::vec![0u8; 0x1000];
    let base = memory.as_mut_ptr() as u64;
    let configure = |mut device: super::ModernNetState| {
        device.hhdm = base;
        device.rxq.size = 2;
        device.rxq.desc_pa = 0x80;
        device.rxq.driver_pa = AVAIL as u64;
        device.rxq.device_pa = USED as u64;
        device.rxq.notify_va = base + NOTIFY as u64;
        device.rx_bufs[0].pa = BUFFER as u64;
        device.rx_bufs[0].len = 512;
        device
    };
    MODERN_DEVS.lock().push(configure(state(8)));
    let stale_dev = VirtioNetDev::new_for(key(8)).unwrap();
    let runtime = ensure_net_runtime(key(8));
    let generation = runtime.rx_assignments.current();
    let stale_owner = stale_dev as alloc::sync::Arc<dyn net::NetDev>;
    install_rx_runtime(key(8), net::NetIfaceId::from_raw(18), stale_owner.clone(),
        generation, runtime);
    assert!(super::shutdown_modern(key(8)));

    MODERN_DEVS.lock().push(configure(state(8)));
    let replacement_dev = VirtioNetDev::new_for(key(8)).unwrap();
    let replacement_runtime = ensure_net_runtime(key(8));
    let replacement_generation = replacement_runtime.rx_assignments.current();
    assert_eq!(replacement_generation, generation);
    let replacement_owner = replacement_dev as alloc::sync::Arc<dyn net::NetDev>;
    assert!(!alloc::sync::Arc::ptr_eq(&stale_owner, &replacement_owner));
    install_rx_runtime(key(8), net::NetIfaceId::from_raw(19), replacement_owner.clone(),
        replacement_generation, replacement_runtime);
    memory[BUFFER + 12..BUFFER + 26].fill(0x5a);
    memory[USED + 2..USED + 4].copy_from_slice(&1u16.to_le_bytes());
    memory[USED + 4..USED + 8].copy_from_slice(&0u32.to_le_bytes());
    memory[USED + 8..USED + 12].copy_from_slice(&FRAME_TOTAL.to_le_bytes());

    assert_eq!(super::super::rx_poll_for(key(8), &stale_owner, generation, |_, _| {}), 0);
    assert_eq!(super::modern_state_for(key(8)).unwrap().rx_last_used, 0);
    assert_eq!(super::super::rx_poll_for(
        key(8), &replacement_owner, replacement_generation, |_, _| {},
    ), 1);
    clear_test_state();
}
