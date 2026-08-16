//! The set of controllers the host knows about.
//!
//! One global registry, because a controller index is a machine-wide name: the
//! management interface, the raw sockets and the monitor all address a
//! controller by it, and a second registry would let two of them disagree about
//! which controller `hci0` is.

extern crate alloc;
use alloc::sync::Arc;
use alloc::vec::Vec;

use sync::{HciDev as HciDevClass, HciRegistry as HciRegistryClass, Spinlock};
use syscall::errno::Errno;

use super::dev::{lowest_free_index, HciDevState};
use super::transport::HciTransport;

/// One registered controller: its state and the transport that carries it.
pub struct HciDev {
    pub index: u16,
    pub state: Spinlock<HciDevState, HciDevClass>,
    transport: Arc<dyn HciTransport>,
}

impl HciDev {
    /// Send one whole H:4 frame down this controller's transport. # C: O(len)
    pub fn send(&self, frame: &[u8]) -> Result<(), Errno> { self.transport.send(frame) }

    /// Bus the controller attaches by. # C: O(1)
    pub fn bus(&self) -> u8 { self.transport.bus() }

    /// Driver name for the device listing. # C: O(1)
    pub fn driver_name(&self) -> alloc::string::String { self.transport.driver_name() }

    /// Open the transport and mark the controller running. # C: O(1)
    pub fn open(&self) -> Result<(), Errno> {
        self.transport.open()?;
        self.state.lock().set_flag(crate::uapi::hci_sock::HCI_RUNNING, true);
        Ok(())
    }

    /// Close the transport and drop everything the controller was holding.
    /// # C: O(n)
    pub fn close(&self) {
        self.transport.close();
        self.state.lock().tear_down();
    }
}

static REGISTRY: Spinlock<Vec<Arc<HciDev>>, HciRegistryClass> = Spinlock::new(Vec::new());

/// Register a controller, allocating it the lowest free index. # C: O(n^2)
/// worst case over the number of controllers, which is small
pub fn register(transport: Arc<dyn HciTransport>) -> Result<Arc<HciDev>, Errno> {
    let mut reg = REGISTRY.lock();
    let taken: Vec<u16> = reg.iter().map(|d| d.index).collect();
    let index = lowest_free_index(&taken).ok_or(Errno::Enfile)?;
    let bus = transport.bus();
    let dev = Arc::new(HciDev {
        index,
        state: Spinlock::new(HciDevState::new(index, bus)),
        transport,
    });
    reg.push(Arc::clone(&dev));
    Ok(dev)
}

/// Remove a controller. Returns whether one was removed, so a double
/// unregistration is visible to the caller rather than silent. # C: O(n)
pub fn unregister(index: u16) -> bool {
    let mut reg = REGISTRY.lock();
    match reg.iter().position(|d| d.index == index) {
        Some(at) => { let dev = reg.remove(at); drop(reg); dev.close(); true }
        None => false,
    }
}

/// The controller with this index. # C: O(n)
pub fn by_index(index: u16) -> Option<Arc<HciDev>> {
    REGISTRY.lock().iter().find(|d| d.index == index).cloned()
}

/// Every registered controller's index, in registration order. # C: O(n)
pub fn indexes() -> Vec<u16> { REGISTRY.lock().iter().map(|d| d.index).collect() }

/// Number of registered controllers. # C: O(1)
pub fn count() -> usize { REGISTRY.lock().len() }

/// Every registered controller. # C: O(n)
pub fn all() -> Vec<Arc<HciDev>> { REGISTRY.lock().clone() }
