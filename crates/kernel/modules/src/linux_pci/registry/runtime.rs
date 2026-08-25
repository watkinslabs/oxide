use super::*;
use alloc::vec::Vec;

pub(crate) fn config_read(dev: *const LinuxPciDev, word: usize) -> Option<u32> {
    if let Some(value) = BINDINGS.lock().iter().find(|r| r.dev == dev as usize).map(|r| r.runtime.config[word]) { return Some(value); }
    #[cfg(test)] { return TEST_RUNTIMES.lock().iter().find(|r| r.0 == dev as usize).map(|r| r.1.config[word]); }
    #[cfg(not(test))] { None }
}

pub(crate) fn config_write(dev: *mut LinuxPciDev, word: usize, value: u32) -> bool {
    let mut g = BINDINGS.lock();
    if let Some(rec) = g.iter_mut().find(|r| r.dev == dev as usize) { rec.runtime.config[word] = value; return true; }
    drop(g);
    #[cfg(test)] {
        let mut tests = TEST_RUNTIMES.lock();
        if let Some((_, rec)) = tests.iter_mut().find(|r| r.0 == dev as usize) { rec.config[word] = value; return true; }
        let mut rec = PciRuntime::new();
        rec.config[word] = value;
        tests.push((dev as usize, rec));
        return true;
    }
    #[cfg(not(test))] { false }
}

/// Discard the saved PCI configuration state for one bound device. # C: O(N)
pub(crate) fn discard_saved_config(dev: *mut LinuxPciDev) -> bool {
    let mut g = BINDINGS.lock();
    if let Some(rec) = g.iter_mut().find(|r| r.dev == dev as usize) { rec.runtime.state_saved = false; return true; }
    drop(g);
    #[cfg(test)] {
        if let Some((_, rec)) = TEST_RUNTIMES.lock().iter_mut().find(|r| r.0 == dev as usize) { rec.state_saved = false; return true; }
        return false;
    }
    #[cfg(not(test))] { false }
}

/// Mark a fixed PCI configuration header as the current restore state. # C: O(N)
pub(crate) fn load_saved_config(dev: *mut LinuxPciDev) -> bool {
    let mut g = BINDINGS.lock();
    if let Some(rec) = g.iter_mut().find(|r| r.dev == dev as usize) { rec.runtime.state_saved = true; return true; }
    drop(g);
    #[cfg(test)] {
        if let Some((_, rec)) = TEST_RUNTIMES.lock().iter_mut().find(|r| r.0 == dev as usize) { rec.state_saved = true; return true; }
        return false;
    }
    #[cfg(not(test))] { false }
}

#[cfg(test)]
pub(crate) fn test_state_saved(dev: *const LinuxPciDev) -> bool {
    TEST_RUNTIMES.lock().iter().find(|r| r.0 == dev as usize).is_some_and(|r| r.1.state_saved)
}

pub(crate) fn irq_vectors(dev: *const LinuxPciDev) -> Option<(u32, i32, u32)> {
    if let Some(value) = BINDINGS.lock().iter().find(|r| r.dev == dev as usize)
        .map(|r| (r.runtime.irq_vector_base, r.runtime.irq_vectors, r.runtime.irq_vector_flags)) { return Some(value); }
    #[cfg(test)] { return TEST_RUNTIMES.lock().iter().find(|r| r.0 == dev as usize)
        .map(|r| (r.1.irq_vector_base, r.1.irq_vectors, r.1.irq_vector_flags)); }
    #[cfg(not(test))] { None }
}

/// Return the Linux IRQ assigned to one device-relative vector. # C: O(N)
pub(crate) fn irq_vector(dev: *const LinuxPciDev, nr: u32) -> Option<u32> {
    if let Some(value) = BINDINGS.lock().iter().find(|r| r.dev == dev as usize)
        .and_then(|r| r.runtime.irq_vector_ids.get(nr as usize).copied()) { return Some(value); }
    #[cfg(test)] { return TEST_RUNTIMES.lock().iter().find(|r| r.0 == dev as usize)
        .and_then(|r| r.1.irq_vector_ids.get(nr as usize).copied()); }
    #[cfg(not(test))] { None }
}

pub(crate) fn set_irq_vectors(dev: *mut LinuxPciDev, base: u32, count: i32, flags: u32) -> bool {
    let mut ids = Vec::new();
    for off in 0..count.max(0) { ids.push(base.wrapping_add(off as u32)); }
    set_irq_vector_list(dev, ids, flags, 0)
}

/// Publish all device-relative IRQ identities and retain an optional MSI-X
/// table mapping. The vector list is authoritative; `irq_vector_base` remains
/// only for existing ABI bookkeeping and legacy callers. # C: O(N)
pub(crate) fn set_irq_vector_list(dev: *mut LinuxPciDev, ids: Vec<u32>, flags: u32, mapping: usize) -> bool {
    let base = ids.first().copied().unwrap_or(0);
    let count = ids.len() as i32;
    let mut g = BINDINGS.lock();
    if let Some(rec) = g.iter_mut().find(|r| r.dev == dev as usize) {
        rec.runtime.irq_vector_base = base; rec.runtime.irq_vectors = count; rec.runtime.irq_vector_flags = flags;
        rec.runtime.irq_vector_ids = ids; rec.runtime.irq_mapping = mapping; return true;
    }
    drop(g);
    #[cfg(test)] {
        let mut tests = TEST_RUNTIMES.lock();
        if let Some((_, rec)) = tests.iter_mut().find(|r| r.0 == dev as usize) {
            rec.irq_vector_base = base; rec.irq_vectors = count; rec.irq_vector_flags = flags;
            rec.irq_vector_ids = ids; rec.irq_mapping = mapping; return true;
        }
        let mut rec = PciRuntime::new();
        rec.irq_vector_base = base; rec.irq_vectors = count; rec.irq_vector_flags = flags;
        rec.irq_vector_ids = ids; rec.irq_mapping = mapping;
        tests.push((dev as usize, rec));
        return true;
    }
    #[cfg(not(test))] { false }
}

/// Withdraw the current interrupt binding and transfer its IRQ/table mapping
/// ownership to the PCI teardown path. # C: O(N)
pub(crate) fn take_irq_vector_list(dev: *mut LinuxPciDev) -> Option<(Vec<u32>, u32, usize)> {
    let mut g = BINDINGS.lock();
    if let Some(rec) = g.iter_mut().find(|r| r.dev == dev as usize) {
        let ids = core::mem::take(&mut rec.runtime.irq_vector_ids);
        let flags = rec.runtime.irq_vector_flags;
        let mapping = core::mem::replace(&mut rec.runtime.irq_mapping, 0);
        rec.runtime.irq_vector_base = 0; rec.runtime.irq_vectors = 0; rec.runtime.irq_vector_flags = 0;
        return Some((ids, flags, mapping));
    }
    drop(g);
    #[cfg(test)] {
        let mut tests = TEST_RUNTIMES.lock();
        let (_, rec) = tests.iter_mut().find(|r| r.0 == dev as usize)?;
        let ids = core::mem::take(&mut rec.irq_vector_ids);
        let flags = rec.irq_vector_flags;
        let mapping = core::mem::replace(&mut rec.irq_mapping, 0);
        rec.irq_vector_base = 0; rec.irq_vectors = 0; rec.irq_vector_flags = 0;
        return Some((ids, flags, mapping));
    }
    #[cfg(not(test))] { None }
}

pub(crate) fn set_wake_enabled(dev: *mut LinuxPciDev, enabled: bool) -> bool {
    let mut g = BINDINGS.lock();
    if let Some(rec) = g.iter_mut().find(|r| r.dev == dev as usize) { rec.runtime.wake_enabled = enabled; return true; }
    drop(g);
    #[cfg(test)] {
        if let Some((_, rec)) = TEST_RUNTIMES.lock().iter_mut().find(|r| r.0 == dev as usize) { rec.wake_enabled = enabled; return true; }
        return false;
    }
    #[cfg(not(test))] { false }
}

#[cfg(test)]
pub(crate) fn test_register_runtime(dev: *mut LinuxPciDev) {
    let mut g = TEST_RUNTIMES.lock();
    g.retain(|r| r.0 != dev as usize);
    g.push((dev as usize, PciRuntime::new()));
}

#[cfg(test)]
pub(crate) fn test_wake_enabled(dev: *const LinuxPciDev) -> bool {
    TEST_RUNTIMES.lock().iter().find(|r| r.0 == dev as usize).is_some_and(|r| r.1.wake_enabled)
}
