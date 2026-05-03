// EL1 exception printer per `21§5`. Called from
// `oxide_default_vector_handler` (asm in `vbar.rs`) with the three
// system registers most useful for triage:
//
//   x0 = ESR_EL1   exception syndrome (cause + ISS)
//   x1 = FAR_EL1   fault address (data/instruction abort)
//   x2 = ELR_EL1   return address (instruction at exception)
//
// Emits a one-line summary via `klog::write_raw` then returns; the
// asm caller halts via `wfi` after `bl`.

/// Rust-side EL1 fault printer.
///
/// # SAFETY: caller is the shared default vector handler. We only
/// read function arguments; klog uses the global byte sink.
/// # C: O(constant)
/// # Ctx: exception, IRQ-off (DAIF set by handler)
#[no_mangle]
pub unsafe extern "C" fn oxide_fault_print_rust(esr: u64, far: u64, elr: u64) {
    klog::write_raw(b"[FAULT] esr=");
    klog::write_hex_u64(esr);
    klog::write_raw(b" far=");
    klog::write_hex_u64(far);
    klog::write_raw(b" elr=");
    klog::write_hex_u64(elr);
    klog::write_raw(b"\n");
}
