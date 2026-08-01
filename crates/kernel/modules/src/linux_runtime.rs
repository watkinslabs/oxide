// Linux compiler/runtime compatibility exports.

use core::ffi::c_void;
use core::sync::atomic::{AtomicUsize, Ordering};

const CPU_MASK_WORDS: usize = 1;
const TRACE_EVENT_ENABLED: i32 = 0;
const TRACE_EVENT_IGNORED: i32 = 0;

#[repr(C, align(8))]
struct CpuMask {
    bits: [usize; CPU_MASK_WORDS],
}

#[unsafe(no_mangle)]
static __preempt_count: i32 = 0;
#[unsafe(no_mangle)]
static __num_online_cpus: i32 = 1;
#[unsafe(no_mangle)]
static nr_cpu_ids: u32 = 1;
#[unsafe(no_mangle)]
static __cpu_online_mask: CpuMask = CpuMask { bits: [1] };
#[unsafe(no_mangle)]
static __cpu_possible_mask: CpuMask = CpuMask { bits: [1] };
#[unsafe(no_mangle)]
static __per_cpu_offset: [usize; 1] = [0];
#[unsafe(no_mangle)]
static this_cpu_off: usize = 0;
#[unsafe(no_mangle)]
static cpu_number: u32 = 0;
#[unsafe(no_mangle)]
static system_state: u32 = 0;

static RATELIMIT_TOKENS: AtomicUsize = AtomicUsize::new(usize::MAX);

/// Register Linux compiler/runtime KPI symbols.
/// # C: O(1)
pub fn export_symbols() {
    use crate::symtab::export;
    for (name, addr) in [
        ("__ubsan_handle_out_of_bounds", ubsan_handle as *const () as usize),
        ("__ubsan_handle_shift_out_of_bounds", ubsan_handle as *const () as usize),
        ("__SCT__cond_resched", cond_resched as *const () as usize),
        ("__SCT__might_resched", might_resched as *const () as usize),
        ("__SCT__preempt_schedule", preempt_schedule as *const () as usize),
        ("__list_add_valid_or_report", list_valid_or_report as *const () as usize),
        ("__list_del_entry_valid_or_report", list_valid_or_report as *const () as usize),
        ("___ratelimit", ratelimit as *const () as usize),
        ("net_ratelimit", net_ratelimit as *const () as usize),
        ("dump_stack", dump_stack as *const () as usize),
        ("trace_seq_printf", trace_seq_printf as *const () as usize),
        ("trace_seq_putc", trace_seq_putc as *const () as usize),
        ("__trace_trigger_soft_disabled", trace_trigger_soft_disabled as *const () as usize),
        ("trace_event_buffer_reserve", trace_event_buffer_reserve as *const () as usize),
        ("trace_event_buffer_commit", trace_event_buffer_commit as *const () as usize),
        ("trace_event_printf", trace_event_printf as *const () as usize),
        ("trace_event_raw_init", trace_event_raw_init as *const () as usize),
        ("trace_event_reg", trace_event_reg as *const () as usize),
        ("trace_handle_return", trace_handle_return as *const () as usize),
        ("trace_raw_output_prep", trace_raw_output_prep as *const () as usize),
        ("trace_print_hex_seq", trace_print_seq as *const () as usize),
        ("trace_print_symbols_seq", trace_print_seq as *const () as usize),
        ("perf_trace_buf_alloc", perf_trace_buf_alloc as *const () as usize),
        ("perf_trace_run_bpf_submit", perf_trace_run_bpf_submit as *const () as usize),
        ("bpf_trace_run1", bpf_trace_run as *const () as usize),
        ("bpf_trace_run2", bpf_trace_run as *const () as usize),
        ("bpf_trace_run3", bpf_trace_run as *const () as usize),
    ] { export(name, addr, false); }
    export("__preempt_count", &__preempt_count as *const _ as usize, false);
    export("__num_online_cpus", &__num_online_cpus as *const _ as usize, false);
    export("nr_cpu_ids", &nr_cpu_ids as *const _ as usize, false);
    export("__cpu_online_mask", &__cpu_online_mask as *const _ as usize, false);
    export("__cpu_possible_mask", &__cpu_possible_mask as *const _ as usize, false);
    export("__per_cpu_offset", __per_cpu_offset.as_ptr() as usize, false);
    export("this_cpu_off", &this_cpu_off as *const _ as usize, false);
    export("cpu_number", &cpu_number as *const _ as usize, false);
    export("system_state", &system_state as *const _ as usize, false);
    export_arch_symbols();
}

#[cfg(all(target_arch = "x86_64", target_os = "oxide-kernel"))]
fn export_arch_symbols() {
    use crate::symtab::export;
    use hal_x86_64::linux_retpoline;
    for (name, addr) in [
        ("__x86_return_thunk", linux_retpoline::__x86_return_thunk as *const () as usize),
        ("__x86_indirect_thunk_rax", linux_retpoline::__x86_indirect_thunk_rax as *const () as usize),
        ("__x86_indirect_thunk_rbx", linux_retpoline::__x86_indirect_thunk_rbx as *const () as usize),
        ("__x86_indirect_thunk_rcx", linux_retpoline::__x86_indirect_thunk_rcx as *const () as usize),
        ("__x86_indirect_thunk_rdx", linux_retpoline::__x86_indirect_thunk_rdx as *const () as usize),
        ("__x86_indirect_thunk_r8", linux_retpoline::__x86_indirect_thunk_r8 as *const () as usize),
        ("__x86_indirect_thunk_r10", linux_retpoline::__x86_indirect_thunk_r10 as *const () as usize),
        ("__x86_indirect_thunk_r12", linux_retpoline::__x86_indirect_thunk_r12 as *const () as usize),
        ("__x86_indirect_thunk_r14", linux_retpoline::__x86_indirect_thunk_r14 as *const () as usize),
    ] { export(name, addr, false); }
}

#[cfg(not(all(target_arch = "x86_64", target_os = "oxide-kernel")))]
fn export_arch_symbols() {}

extern "C" fn ubsan_handle() {}
extern "C" fn cond_resched() -> i32 { 0 }
extern "C" fn might_resched() {}
extern "C" fn preempt_schedule() {}
extern "C" fn dump_stack() {}

extern "C" fn list_valid_or_report(_a: *const c_void, _b: *const c_void, _c: *const c_void) -> bool {
    true
}

extern "C" fn ratelimit(_state: *mut c_void, _func: *const u8) -> i32 {
    let old = RATELIMIT_TOKENS.load(Ordering::Relaxed);
    if old == 0 { 0 } else { 1 }
}

extern "C" fn net_ratelimit() -> i32 { 1 }
extern "C" fn trace_seq_printf(_seq: *mut c_void, _fmt: *const u8) -> i32 { 0 }
extern "C" fn trace_seq_putc(_seq: *mut c_void, _c: u8) {}
extern "C" fn trace_trigger_soft_disabled(_file: *mut c_void) -> i32 { TRACE_EVENT_ENABLED }
extern "C" fn trace_event_buffer_reserve() -> *mut c_void { core::ptr::null_mut() }
extern "C" fn trace_event_buffer_commit(_buf: *mut c_void) {}
extern "C" fn trace_event_printf(_iter: *mut c_void, _fmt: *const u8) -> i32 { TRACE_EVENT_IGNORED }
extern "C" fn trace_event_raw_init(_call: *mut c_void) -> i32 { 0 }
extern "C" fn trace_event_reg(_call: *mut c_void, _type: i32, _data: *mut c_void) -> i32 { 0 }
extern "C" fn trace_handle_return(_s: *mut c_void) {}
extern "C" fn trace_raw_output_prep(_iter: *mut c_void, _event: *mut c_void) -> i32 { 0 }
extern "C" fn trace_print_seq(_p: *mut c_void, _seq: *mut c_void) -> i32 { 0 }
extern "C" fn perf_trace_buf_alloc(_size: i32, _rctxp: *mut i32) -> *mut c_void { core::ptr::null_mut() }
extern "C" fn perf_trace_run_bpf_submit() {}
extern "C" fn bpf_trace_run() {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn runtime_exports_cover_compiler_scheduler_trace_surface() {
        let _modules = crate::test_serial::claim();
        export_symbols();
        for name in [
            "__ubsan_handle_out_of_bounds", "__ubsan_handle_shift_out_of_bounds",
            "__SCT__cond_resched", "__SCT__might_resched", "__SCT__preempt_schedule",
            "__preempt_count", "__cpu_online_mask", "__cpu_possible_mask", "nr_cpu_ids",
            "__list_add_valid_or_report", "__list_del_entry_valid_or_report", "___ratelimit",
            "trace_seq_printf", "trace_seq_putc", "trace_event_buffer_reserve",
            "perf_trace_run_bpf_submit", "bpf_trace_run1",
        ] {
            assert!(crate::symtab::is_exported(name), "{name}");
        }
    }

    #[test]
    fn scheduler_and_list_compat_paths_are_safe_defaults() {
        let _modules = crate::test_serial::claim();
        assert_eq!(cond_resched(), 0);
        might_resched();
        preempt_schedule();
        assert!(list_valid_or_report(core::ptr::null(), core::ptr::null(), core::ptr::null()));
        assert_eq!(net_ratelimit(), 1);
    }
}
