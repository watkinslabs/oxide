use super::{VirtioChildTransportSession, VirtioChildDeviceKey, VirtioChildDriverId, VirtioTransportProfile, VIRTIO_CHILD_BUS};
use alloc::sync::Arc;
use core::marker::PhantomData;

/// Concrete bus adapter for model-owned virtio child drivers.
pub trait VirtioChildBus: Sync {
    type Session: VirtioChildTransportSession;

    /// Begin transport-specific child probe state for a model device.
    /// # C: O(transport_probe)
    fn begin_session(
        dev: &drv::Device,
        profile: VirtioTransportProfile,
    ) -> drv::KResult<Self::Session>;

    /// Resolve the stable child runtime key from a model device.
    /// # C: O(1)
    fn parent_key(dev: &drv::Device) -> Option<VirtioChildDeviceKey>;

    /// Drop transport-owned runtime state after child remove.
    /// # C: O(N_transport_resources)
    fn unpublish_transport(device_key: VirtioChildDeviceKey);
}

/// Child-driver callbacks behind the shared virtio model-driver adapter.
pub trait VirtioChildDriverOps<S: VirtioChildTransportSession>: Sync {
    const DRIVER_ID: VirtioChildDriverId;

    /// Transport profile requested by this child driver.
    /// # C: O(1)
    fn profile() -> VirtioTransportProfile;

    /// Install child runtime state before the transport becomes visible.
    /// # C: O(child_probe)
    fn probe_child(parent: &Arc<drv::Device>, session: &mut S) -> drv::KResult<()>;

    /// Queue process-context work only after transport publication is complete.
    /// # C: O(1)
    fn child_published(_device_key: VirtioChildDeviceKey) {}

    /// Remove child runtime state before transport teardown.
    /// # C: O(child_remove)
    fn remove_child(device_key: VirtioChildDeviceKey);

    /// Quiesce child runtime state for power/reboot shutdown.
    /// # C: O(child_shutdown)
    fn shutdown_child(device_key: VirtioChildDeviceKey);
}

/// Shared virtio child model-driver adapter.
pub struct VirtioChildDriver<B, O> {
    _bus: PhantomData<B>,
    _ops: PhantomData<O>,
}

impl<B, O> VirtioChildDriver<B, O> {
    /// # C: O(1)
    pub const fn new() -> Self {
        Self { _bus: PhantomData, _ops: PhantomData }
    }
}

impl<B, O> drv::Driver for VirtioChildDriver<B, O>
where
    B: VirtioChildBus,
    O: VirtioChildDriverOps<B::Session>,
{
    fn bus(&self) -> &'static str { VIRTIO_CHILD_BUS }

    fn name(&self) -> &'static str { O::DRIVER_ID.name }

    fn matches(&self, dev: &drv::Device) -> bool {
        O::DRIVER_ID.matches_device(&dev.bus, dev.vendor_id, dev.device_id)
    }

    fn probe(&self, dev: &Arc<drv::Device>) -> drv::KResult<()> {
        let session = B::begin_session(dev, O::profile())?;
        run_child_probe_after_publish(
            session,
            |session| O::probe_child(dev, session),
            O::child_published,
        )
    }

    fn remove(&self, dev: &drv::Device) {
        if let Some(device_key) = B::parent_key(dev) {
            run_child_remove(device_key, O::remove_child, B::unpublish_transport);
        }
    }

    fn shutdown(&self, dev: &drv::Device) {
        if let Some(device_key) = B::parent_key(dev) {
            run_child_shutdown(device_key, O::shutdown_child);
        }
    }
}

/// Run a child probe against a transport session, publishing transport-owned
/// state only after the child succeeds and releasing failed-probe resources on
/// child error.
/// # C: O(child_probe + N_transport_resources)
pub fn run_child_probe<S, E, F>(session: S, probe: F) -> Result<(), E>
where
    S: VirtioChildTransportSession,
    F: FnOnce(&mut S) -> Result<(), E>,
{
    run_child_probe_after_publish(session, probe, |_| {})
}

/// Run a child probe, publish its transport state, then invoke its post-publish
/// work hook with the stable key. The hook cannot fail because publication is
/// already visible and owns the child transport lifetime.
/// # C: O(child_probe + N_transport_resources)
pub fn run_child_probe_after_publish<S, E, F, P>(mut session: S, probe: F, published: P) -> Result<(), E>
where
    S: VirtioChildTransportSession,
    F: FnOnce(&mut S) -> Result<(), E>,
    P: FnOnce(VirtioChildDeviceKey),
{
    match probe(&mut session) {
        Ok(()) => {
            let device_key = session.device_key();
            session.publish();
            published(device_key);
            Ok(())
        }
        Err(e) => {
            session.release_failed_child();
            Err(e)
        }
    }
}

/// Run child remove before unpublishing transport-owned state.
/// # C: O(child_remove + N_transport_resources)
pub fn run_child_remove<R, U>(device_key: VirtioChildDeviceKey, remove: R, unpublish: U)
where
    R: FnOnce(VirtioChildDeviceKey),
    U: FnOnce(VirtioChildDeviceKey),
{
    remove(device_key);
    unpublish(device_key);
}

/// Run child shutdown for a stable child key.
/// # C: O(child_shutdown)
pub fn run_child_shutdown<S>(device_key: VirtioChildDeviceKey, shutdown: S)
where
    S: FnOnce(VirtioChildDeviceKey),
{
    shutdown(device_key);
}
