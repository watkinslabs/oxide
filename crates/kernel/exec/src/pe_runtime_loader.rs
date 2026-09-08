//! The user-mode loader handover.
//!
//! The kernel maps exactly two images — the executable and the runtime module
//! — builds the process and thread blocks, and enters the runtime's own
//! initialization thunk with a context describing the thread the process is to
//! start on. The runtime loads the rest of the module graph, binds every
//! import, creates the process heap, and resumes on that context. Nothing here
//! walks the graph: that is the point.
//!
//! The context is built on the initial thread stack and the thread enters
//! with the stack pointer just below it. That placement is load-bearing, not
//! cosmetic: the thunk's thread-start path rounds the pointer it is given down
//! to a page and zeroes a fixed extent below it, running on that extent as its
//! own stack, so the record must sit on a mapping that extends that far below
//! it. `startup_stack` owns the arithmetic.

use hal::UserVirtAddr;
use pe::nt_context;
use vmm::AddressSpace;

use crate::pe_loader::{ExecutionPersonality, PeEntryState, PeLoadedImage};
use crate::process_env;

#[path = "pe_runtime_loader/startup_stack.rs"]
pub mod startup_stack;

/// The runtime module every NT process enters through.
pub const RUNTIME_MODULE: &[u8] = b"ntdll.dll";
/// The runtime's initialization entry, which the module publishes by name.
pub const RUNTIME_INIT_ENTRY: &[u8] = b"LdrInitializeThunk";
/// Data the runtime module exports for the kernel side to fill in: the two
/// dispatcher pointers it calls through and the identity of the Unix-call
/// table. The module publishes the slots and reads them; it never writes
/// them, so an unfilled slot is a call through a null pointer.
pub const RUNTIME_SLOT_NAMES: [&[u8]; 3] =
    [b"__wine_syscall_dispatcher", b"__wine_unix_call_dispatcher", b"__wine_unixlib_handle"];
/// Windows paths the two mapped modules are published under.
const RUNTIME_PATH: &str = "C:\\Windows\\System32\\ntdll.dll";

/// A process handed over to its own runtime loader.
pub struct RuntimeHandover {
    pub image: PeLoadedImage,
    pub runtime: PeLoadedImage,
    pub environment: process_env::NtProcessEnvironment,
    pub entry: PeEntryState,
    /// Value the initialization thunk reads from the first argument register.
    pub context: UserVirtAddr,
    /// The record itself, for the caller that materialises it in the address
    /// space being built. Placement is decided here; the write needs a
    /// populated foreign mapping, which only the kernel target can do.
    pub context_image: [u8; nt_context::CONTEXT_BYTES],
    pub startup: crate::pe_startup::PeStartupTransaction,
}

impl RuntimeHandover {
    /// The loaded process, in the shape every launch path consumes. The
    /// handover builds no kernel-side initializer list: attaching the module
    /// graph is the runtime's own work.
    /// # C: O(1)
    pub fn into_process(self) -> crate::pe_loader::PeProcess {
        crate::pe_loader::PeProcess {
            image: self.image, environment: self.environment, entry: self.entry,
            startup: self.startup, initializers: alloc::vec::Vec::new(), initializer_trampoline: None,
        }
    }
}

/// Map the executable and the runtime module, publish the process blocks, and
/// return the entry state that enters the runtime's initialization thunk.
/// # C: O(image bytes + runtime bytes)
pub fn load(blob: &[u8], runtime_blob: &[u8], as_: &AddressSpace,
    input: &process_env::EnvironmentInput<'_>, stack_base: u64, stack_top: u64)
    -> Result<RuntimeHandover, pe::Error> {
    // The module's own service numbering, before anything is mapped.
    let runtime_parsed = pe::parse(runtime_blob)?;
    let _ = crate::nt_ordinals::install_from_image(&runtime_parsed);

    // The runtime support region is mapped before either image so the module
    // can be published with its data slots already pointing at real code.
    let support = crate::pe_loader::nt_support::map_and_publish(as_)?;
    let slots = runtime_slots(&runtime_parsed, &support)?;

    let image = crate::pe_loader::load_pe_image_unbound(blob, as_)?;
    let runtime = crate::pe_loader::load_pe_image_unbound_with_slots(runtime_blob, as_, &slots)?;
    let init = runtime_init_entry(&runtime_parsed, runtime.base)?;

    let mut environment_input = input.clone();
    environment_input.image_base = image.base;
    environment_input.image_size = image.size;
    let modules = [
        process_env::NtModuleInput { base: image.base, entry: image.entry.as_u64(), size: image.size,
            full_name: input.image_path, base_name: base_name(input.image_path) },
        process_env::NtModuleInput { base: runtime.base, entry: runtime.entry.as_u64(), size: runtime.size,
            full_name: RUNTIME_PATH, base_name: "ntdll.dll" },
    ];
    let environment = process_env::build_for_runtime_loader(&environment_input, &modules,
        &process_env::NtProcessParameters::default_for(), stack_base, stack_top, as_)?;

    let entry_state = crate::pe_loader::initial_entry_state_with_environment(&image, stack_top, &environment)?;
    let placed = startup_stack::place(stack_base, stack_top).ok_or(pe::Error::Einval)?;
    let context = UserVirtAddr::new(placed.context).ok_or(pe::Error::Einval)?;
    let context_image = nt_context::startup_context(image.entry.as_u64(), 0, entry_state.rsp.as_u64());
    let rsp = UserVirtAddr::new(placed.stack_pointer).ok_or(pe::Error::Einval)?;
    let entry = PeEntryState { rip: init, rsp, rcx: context.as_u64(),
        gs_base: entry_state.gs_base, personality: ExecutionPersonality::Nt };
    let startup = crate::pe_startup::PeStartupTransaction::begin_with_transfer(as_, &image, &environment,
        stack_base, stack_top, &entry, init)?;
    Ok(RuntimeHandover { image, runtime, environment, entry, context, context_image, startup })
}

/// Pair each runtime-owned data slot with the support-region address it must
/// hold. A module missing any of the three cannot be entered: its own
/// initialisation would call through a slot nothing ever writes.
/// # C: O(N_slots * export names)
pub fn runtime_slots(parsed: &pe::Image<'_>, support: &crate::pe_loader::nt_support::NtRuntimeSupport)
    -> Result<[(u32, u64); RUNTIME_SLOT_NAMES.len()], pe::Error>
{
    let values = [support.wine_dispatcher, support.wine_unix_dispatcher, syscall::nt::WINE_UNIXLIB_HANDLE];
    let mut slots = [(0u32, 0u64); RUNTIME_SLOT_NAMES.len()];
    for (index, name) in RUNTIME_SLOT_NAMES.iter().enumerate() {
        let thunk = pe::ImportThunk::Name { hint: 0, name };
        let rva = parsed.export_rva(&thunk)?.ok_or(pe::Error::Unsupported)?;
        slots[index] = (rva, values[index]);
    }
    Ok(slots)
}

/// Resolve the runtime's initialization entry to a mapped user address.
/// # C: O(export names)
pub fn runtime_init_entry(parsed: &pe::Image<'_>, base: u64) -> Result<UserVirtAddr, pe::Error> {
    let thunk = pe::ImportThunk::Name { hint: 0, name: RUNTIME_INIT_ENTRY };
    let rva = parsed.executable_export_rva(&thunk)?.ok_or(pe::Error::Unsupported)?;
    UserVirtAddr::new(base.checked_add(rva as u64).ok_or(pe::Error::Einval)?).ok_or(pe::Error::Einval)
}

/// Materialise the startup context on the thread stack of the address space
/// being built. The pages are populated first: the running task's fault
/// handler resolves against its own address space, not this one.
/// # C: O(CONTEXT_BYTES)
#[cfg(target_os = "oxide-kernel")]
pub fn install_startup_context(as_: &AddressSpace, handover: &RuntimeHandover) -> Result<(), pe::Error> {
    let at = handover.context.as_u64();
    let bytes = nt_context::CONTEXT_BYTES;
    pmm::user_as::prefault_user_range(as_, at, bytes as u64).map_err(|_| pe::Error::Einval)?;
    // SAFETY: install_startup_context's caller retains this AddressSpace, so
    // root_pa names live page tables, and the record's range was just
    // populated writable; write_foreign_user reports the bytes it stored.
    let written = unsafe { pmm::user_as::write_foreign_user(as_.root_pa(), at, &handover.context_image) };
    if written == bytes { Ok(()) } else { Err(pe::Error::Einval) }
}

fn base_name(path: &str) -> &str { path.rsplit(['\\', '/']).next().unwrap_or(path) }

#[cfg(test)]
#[path = "pe_runtime_loader/tests.rs"]
mod tests;
