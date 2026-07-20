use super::*;
use alloc::sync::Arc;
use netlink::{proto, NetlinkSocket};
use sync::TaskList;

const TEST_BLOCK_SIZE: u32 = 512;
const TEST_BLOCK_COUNT: u64 = 8;
const TEST_UEVENT_NAME: &str = "sysfsblk0";
const TEST_QUEUE_NAME: &str = "sysfsblkqueue0";
const TEST_SERIAL_NAME: &str = "sysfsblkserial";
const TEST_SERIAL: &str = "oxahci-test";
const TEST_TOPOLOGY_NAME: &str = "sysfsblktopology";
const EXPECTED_QUEUE_TEXT: &[u8] = b"512\n";
const QUEUE_ATTR_START: u64 = 0;
const TOPOLOGY_LOGICAL_BYTES: u32 = 512;
const TOPOLOGY_PHYSICAL_BYTES: u32 = 4096;
const TOPOLOGY_IO_MIN_BYTES: u32 = TOPOLOGY_PHYSICAL_BYTES;
const TOPOLOGY_IO_OPT_BYTES: u32 = TOPOLOGY_PHYSICAL_BYTES * 2;

struct TopologyDisk { inner: Arc<block::MemDisk<TaskList>>, limits: block::QueueLimits }
impl block::BlockDevice for TopologyDisk {
    fn block_size(&self) -> u32 { self.inner.block_size() }
    fn queue_limits(&self) -> block::KResult<block::QueueLimits> { Ok(self.limits) }
    fn capacity_blocks(&self) -> u64 { self.inner.capacity_blocks() }
    fn submit_sync(&self, request: &mut block::BlockRequest) -> block::KResult<()> { self.inner.submit_sync(request) }
    fn flush(&self) -> block::KResult<()> { self.inner.flush() }
}

#[test]
fn block_uevent_write_reemits_model_event() {
    let dev: Arc<dyn block::BlockDevice> = block::MemDisk::<TaskList>::new(TEST_BLOCK_SIZE, TEST_BLOCK_COUNT);
    let index = block::registry::register(TEST_UEVENT_NAME, dev);
    assert_ne!(index, 0);
    let listener = Arc::new(NetlinkSocket::new(proto::NETLINK_KOBJECT_UEVENT, &network_namespace::initial()));
    listener.set_group_mask(1);
    netlink::register_uevent_listener(&listener);

    let root = make_sys_block_inode();
    let dir = root.lookup(TEST_UEVENT_NAME).expect("disk dir");
    let uevent = dir.lookup("uevent").expect("uevent attr");
    assert_eq!(uevent.write(0, b"change\n"), Ok("change\n".len()));
    let (msg, _src) = listener.dequeue().expect("uevent message");
    assert!(msg.windows(b"ACTION=change".len()).any(|w| w == b"ACTION=change"));
    assert!(msg.windows(b"DEVPATH=/devices/virtual/block/sysfsblk0".len()).any(|w| w == b"DEVPATH=/devices/virtual/block/sysfsblk0"));
    assert!(msg.windows(b"SUBSYSTEM=block".len()).any(|w| w == b"SUBSYSTEM=block"));
    assert!(msg.windows(b"DEVNAME=sysfsblk0".len()).any(|w| w == b"DEVNAME=sysfsblk0"));
    assert!(msg.windows(b"DEVTYPE=disk".len()).any(|w| w == b"DEVTYPE=disk"));

    assert!(block::registry::unregister(TEST_UEVENT_NAME));
}

#[test]
fn block_device_serial_reads_registry_identity() {
    let dev: Arc<dyn block::BlockDevice> = block::MemDisk::<TaskList>::new(TEST_BLOCK_SIZE, TEST_BLOCK_COUNT);
    let index = block::registry::register_with_serial(TEST_SERIAL_NAME, Some(TEST_SERIAL), dev);
    assert_ne!(index, 0);

    let root = make_sys_block_inode();
    let dir = root.lookup(TEST_SERIAL_NAME).expect("disk dir");
    let device = dir.lookup("device").expect("device dir");
    let serial = device.lookup("serial").expect("serial attr");
    let mut buf = [0u8; 32];
    let n = serial.read(0, &mut buf).expect("read serial");
    assert_eq!(&buf[..n], b"oxahci-test\n");

    assert!(block::registry::unregister(TEST_SERIAL_NAME));
}

#[test]
fn block_queue_renders_one_canonical_topology_record() {
    let dev: Arc<dyn block::BlockDevice> = block::MemDisk::<TaskList>::new(TEST_BLOCK_SIZE, TEST_BLOCK_COUNT);
    assert_ne!(block::registry::register(TEST_QUEUE_NAME, dev), 0);

    let root = make_sys_block_inode();
    let dir = root.lookup(TEST_QUEUE_NAME).expect("disk dir");
    let queue = dir.lookup("queue").expect("queue dir");
    for name in ["logical_block_size", "physical_block_size", "minimum_io_size", "optimal_io_size"] {
        let attr = queue.lookup(name).expect("queue attr");
        let mut out = [0u8; EXPECTED_QUEUE_TEXT.len()];
        let count = attr.read(QUEUE_ATTR_START, &mut out).expect("queue read");
        let expected = if name == "optimal_io_size" { b"0\n" } else { EXPECTED_QUEUE_TEXT };
        assert_eq!(&out[..count], expected);
    }
    assert!(block::registry::unregister(TEST_QUEUE_NAME));
}

#[test]
fn block_queue_does_not_recompute_physical_or_io_topology_from_logical_size() {
    let limits = block::QueueLimits::new(TOPOLOGY_LOGICAL_BYTES,
        TOPOLOGY_PHYSICAL_BYTES, TOPOLOGY_IO_MIN_BYTES, TOPOLOGY_IO_OPT_BYTES).unwrap();
    let inner = block::MemDisk::<TaskList>::new(TOPOLOGY_LOGICAL_BYTES, TEST_BLOCK_COUNT);
    let dev: Arc<dyn block::BlockDevice> = Arc::new(TopologyDisk { inner, limits });
    assert_ne!(block::registry::register(TEST_TOPOLOGY_NAME, dev), 0);

    let root = make_sys_block_inode();
    let queue = root.lookup(TEST_TOPOLOGY_NAME).expect("disk dir").lookup("queue").expect("queue dir");
    for (name, expected) in [
        ("logical_block_size", b"512\n".as_slice()),
        ("physical_block_size", b"4096\n".as_slice()),
        ("minimum_io_size", b"4096\n".as_slice()),
        ("optimal_io_size", b"8192\n".as_slice()),
    ] {
        let attr = queue.lookup(name).expect("queue attr");
        let mut out = [0u8; 16];
        let count = attr.read(QUEUE_ATTR_START, &mut out).expect("queue read");
        assert_eq!(&out[..count], expected);
    }
    assert!(block::registry::unregister(TEST_TOPOLOGY_NAME));
}
