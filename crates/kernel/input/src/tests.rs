use crate::{
    count, device, evdev_id_for_device, install, remove_device, CapBitmap, EvdevHooks,
    InputEvent, InputValue, VirtioInputAbsInfo, VirtioInputDev, VirtioInputDevIds,
    VirtioInputEvent, DEFAULT_REPEAT,
};

mod abi;
mod disposition;
mod identity;
mod lifecycle;
mod semantics;

const TEST_NAME: &[u8] = b"oxide-input";
const TEST_SERIAL: &[u8] = b"input-serial";
const TEST_KEY_CODE: u16 = 30;
const NORMAL_SYNC_VALUE: i32 = 0;

fn key(raw: u32) -> virtio::VirtioChildDeviceKey {
    virtio::VirtioChildDeviceKey::from_raw(raw)
}

fn advertise(bits: &mut [u8], code: u16) {
    bits[(code / u8::BITS as u16) as usize] |= 1 << (code % u8::BITS as u16);
}

fn test_dev(device_key: virtio::VirtioChildDeviceKey) -> alloc::boxed::Box<VirtioInputDev> {
    let mut dev = VirtioInputDev::empty_boxed(device_key);
    dev.is_pointer = true;
    dev.name[..TEST_NAME.len()].copy_from_slice(TEST_NAME);
    dev.name_len = TEST_NAME.len();
    dev.name_present = true;
    dev.serial[..TEST_SERIAL.len()].copy_from_slice(TEST_SERIAL);
    dev.serial_len = TEST_SERIAL.len();
    dev.serial_present = true;
    advertise(&mut dev.key_bits.bits, TEST_KEY_CODE);
    dev.repeat = DEFAULT_REPEAT;
    dev
}

// `crate::registry` is a process-global input-device table, exactly as the
// kernel owns one input registry. Tests which clear it must serialize.
static TEST_MUTEX: std::sync::Mutex<()> = std::sync::Mutex::new(());
static PUSHED_EVENTS: std::sync::Mutex<std::vec::Vec<(u32, u16, u16, i32)>> =
    std::sync::Mutex::new(std::vec::Vec::new());
static PACKET_LENGTHS: std::sync::Mutex<std::vec::Vec<usize>> =
    std::sync::Mutex::new(std::vec::Vec::new());
static OUTPUT_BATCHES: std::sync::Mutex<
    std::vec::Vec<(u32, std::vec::Vec<(u16, u16, i32)>)>,
> = std::sync::Mutex::new(std::vec::Vec::new());

fn record_packet(id: u32, _is_pointer: bool, values: &[InputValue]) {
    if values.last().is_some_and(|value| {
        value.ev_type == crate::EV_SYN
            && value.code == crate::SYN_REPORT
            && value.value == NORMAL_SYNC_VALUE
    }) {
        assert!(
            crate::device(id).is_some(),
            "packet sink runs after the canonical device lock is released",
        );
    }
    PACKET_LENGTHS.lock().unwrap_or_else(|err| err.into_inner()).push(values.len());
    PUSHED_EVENTS.lock().unwrap_or_else(|err| err.into_inner())
        .extend(values.iter().map(|value| (id, value.ev_type, value.code, value.value)));
}

fn record_output(key: virtio::VirtioChildDeviceKey, batch: &crate::OutputBatch) {
    assert!(
        crate::evdev_id_for_device(key).is_some(),
        "output sink runs after the canonical device lock is released",
    );
    let events = batch.events.iter()
        .map(|event| (event.ev_type, event.code, event.value))
        .collect();
    OUTPUT_BATCHES.lock().unwrap_or_else(|err| err.into_inner())
        .push((key.raw(), events));
}

/// One device record must never be cheap to put on a kernel stack: it is
/// kilobytes wide, and the bind path that builds one already sits several
/// frames deep inside a syscall. Copies of it are what overflowed the 16 KiB
/// kernel stack when a virtio-input child was rebound through sysfs.
#[test]
fn a_device_record_is_far_too_wide_for_a_kernel_stack_frame() {
    const KERNEL_STACK_BYTES: usize = 16 * 1024;
    let width = core::mem::size_of::<VirtioInputDev>();
    assert!(
        width > KERNEL_STACK_BYTES / 8,
        "record width {width} no longer justifies the heap-only rule",
    );
}
