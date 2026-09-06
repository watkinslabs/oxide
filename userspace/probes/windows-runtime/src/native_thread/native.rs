use std::{path::{Path, PathBuf}, sync::{Arc, OnceLock}};
use syscall::nt_native_thread::{self as abi, FactoryRequest, Prepared};
use super::gate::{self, Ops};

static NTDLL_PATH: OnceLock<PathBuf> = OnceLock::new();
struct Native;

pub fn install_factory(path: &Path) -> Result<(), u64> {
    NTDLL_PATH.set(path.to_owned()).map_err(|_| abi::INVALID)?;
    status(super::platform::call(abi::REGISTER, super::platform::factory_address(),
        super::platform::factory_return_address(), super::platform::pe_return_address(), abi::VERSION))
}

fn status(value: u64) -> Result<(), u64> { if value == 0 { Ok(()) } else { Err(value) } }

impl Ops for Native {
    fn prepare(&self, request: FactoryRequest) -> Result<Prepared, u64> {
        let mut result = Prepared::default();
        status(super::platform::call(abi::PREPARE, request.creator, request.generation,
            (&mut result as *mut Prepared) as u64, 0))?;
        Ok(result)
    }
    fn attach(&self, prepared: Prepared) -> Result<(), u64> {
        let path = NTDLL_PATH.get().ok_or(abi::NOT_READY)?;
        crate::attach_native_thread(path, prepared.teb, prepared.peb).map_err(|_| abi::NOT_READY)?;
        #[cfg(target_arch = "x86_64")]
        {
            const ARCH_SET_GS: libc::c_int = 0x1001;
            // SAFETY: PREPARE returned this Task's own validated TEB; FS is untouched.
            if unsafe { libc::syscall(libc::SYS_arch_prctl, ARCH_SET_GS, prepared.teb) } != 0 { return Err(abi::INVALID); }
        }
        Ok(())
    }
    fn ready(&self) -> Result<(), u64> { status(super::platform::call(abi::READY, 0, 0, 0, 0)) }
    fn publish(&self) -> Result<(), u64> { status(super::platform::call(abi::PUBLISH, 0, 0, 0, 0)) }
    fn enter(&self) -> u64 {
        // SAFETY: prepared/attached current pthread is released by its creator;
        // ENTER restores this native continuation on PE return or termination.
        unsafe { super::platform::enter() }
    }
    fn release(&self) { let _ = super::platform::call(abi::RELEASE, 0, 0, 0, 0); }
}

pub(super) unsafe fn factory(request: *const FactoryRequest) -> u64 {
    if request.is_null() { return abi::INVALID; }
    // SAFETY: kernel placed the fixed request in the creator's callback frame.
    gate::create(Arc::new(Native), unsafe { *request })
}
