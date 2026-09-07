//! Execute the language-specific handler for real: build scope tables, an
//! exception record and a dispatcher record in host memory, map the emitted
//! body executable, and enter it through the Windows argument registers. The
//! filters, termination handlers and the unwind entry are trampolines that
//! record what they were passed, so every branch is observed rather than
//! inferred.
use super::*;
use alloc::vec;
use alloc::vec::Vec;
use core::ffi::c_void;

const EXCEPTION_UNWINDING: u32 = 0x02;
const EXCEPTION_EXIT_UNWIND: u32 = 0x04;
const EXCEPTION_TARGET_UNWIND: u32 = 0x20;
const EXECUTE_HANDLER: u32 = 1;
const CONTINUE_EXECUTION: i32 = -1;
const CONTINUE_SEARCH_DISPOSITION: u64 = 1;
const CONTINUE_EXECUTION_DISPOSITION: u64 = 0;

const DISPATCHER_BYTES: usize = 0x50;
const CONTROL_PC: usize = 0x00;
const IMAGE_BASE: usize = 0x08;
const TARGET_IP: usize = 0x20;
const CONTEXT_RECORD: usize = 0x28;
const HANDLER_DATA: usize = 0x38;
const HISTORY_TABLE: usize = 0x40;
const SCOPE_INDEX: usize = 0x48;

/// Slots the trampolines record into: the four Windows register arguments,
/// the two stacked ones, and a call counter per trampoline kind.
const LOG_SLOTS: usize = 16;
/// Counter slots, in the order the trampolines are defined.
const FILTER_SEARCH: usize = 6;
const FILTER_EXECUTE: usize = 7;
const FILTER_CONTINUE: usize = 8;
const FINALLY: usize = 9;
const UNWIND: usize = 10;

core::arch::global_asm!(r#"
.data
.p2align 3
.global csh_log
csh_log:
    .zero 128
.text
.macro RECORD
    lea r11, [rip + csh_log]
    mov [r11], rcx
    mov [r11 + 8], rdx
    mov [r11 + 16], r8
    mov [r11 + 24], r9
    mov rax, [rsp + 0x28]
    mov [r11 + 32], rax
    mov rax, [rsp + 0x30]
    mov [r11 + 40], rax
.endm

.global csh_filter_search
csh_filter_search:
    RECORD
    add qword ptr [r11 + 48], 1
    xor eax, eax
    ret

.global csh_filter_execute
csh_filter_execute:
    RECORD
    add qword ptr [r11 + 56], 1
    mov eax, 1
    ret

.global csh_filter_continue
csh_filter_continue:
    RECORD
    add qword ptr [r11 + 64], 1
    mov eax, -1
    ret

.global csh_finally
csh_finally:
    RECORD
    add qword ptr [r11 + 72], 1
    ret

.global csh_unwind
csh_unwind:
    RECORD
    add qword ptr [r11 + 80], 1
    ret

// Enter a stack probe the way compiler-emitted code does and report what
// moved: the accumulator's difference and the stack pointer's.
.global csh_probe_call
csh_probe_call:
    push rbx
    push r12
    mov rbx, rsi
    mov r12, rsp
    mov rax, rsi
    call rdi
    sub rax, rbx
    sub r12, rsp
    mov [rdx], rax
    mov [rdx + 8], r12
    pop r12
    pop rbx
    ret
"#);

unsafe extern "C" {
    static mut csh_log: [u64; LOG_SLOTS];
    fn csh_filter_search();
    fn csh_filter_execute();
    fn csh_filter_continue();
    fn csh_finally();
    fn csh_unwind();
    fn csh_probe_call(code: *const u8, value: u64, moved: *mut ProbeMoved);
    fn mmap(addr: *mut c_void, len: usize, prot: i32, flags: i32, fd: i32, off: i64) -> *mut c_void;
    fn mprotect(addr: *mut c_void, len: usize, prot: i32) -> i32;
    fn munmap(addr: *mut c_void, len: usize) -> i32;
}

fn address_of(routine: unsafe extern "C" fn()) -> u64 { routine as *const () as u64 }

/// Scope records address their handlers as image-relative words, so the
/// fixture's image base is the four-gigabyte-aligned floor of the loaded test
/// code and every handler address becomes an offset from it.
fn image_base() -> u64 { address_of(csh_filter_search) & !0xffff_ffffu64 }
fn rva(address: u64) -> u32 { u32::try_from(address - image_base()).expect("trampoline within the image") }

/// Executable copy of a byte body, with no syscall site to rewrite.
struct Body { address: *mut c_void, len: usize }
impl Body {
    fn new(bytes: &[u8]) -> Self {
        const PROT_RW: i32 = 3;
        const PROT_RX: i32 = 5;
        const MAP_PRIVATE_ANONYMOUS: i32 = 0x22;
        // SAFETY: mmap allocates fresh private storage, copied before mprotect
        // makes the generated test instructions executable and nonwritable.
        unsafe {
            let address = mmap(core::ptr::null_mut(), bytes.len().max(1), PROT_RW, MAP_PRIVATE_ANONYMOUS, -1, 0);
            assert_ne!(address as usize, usize::MAX);
            core::ptr::copy_nonoverlapping(bytes.as_ptr(), address.cast(), bytes.len());
            assert_eq!(mprotect(address, bytes.len().max(1), PROT_RX), 0);
            Self { address, len: bytes.len().max(1) }
        }
    }
    fn enter(&self, record: u64, frame: u64, context: u64, dispatch: u64) -> u64 {
        type Entry = unsafe extern "win64" fn(u64, u64, u64, u64) -> u64;
        // SAFETY: the mapping holds the emitted handler, whose Windows-ABI
        // entry takes exactly these four arguments and returns one word.
        unsafe { core::mem::transmute::<*mut c_void, Entry>(self.address)(record, frame, context, dispatch) }
    }
}
impl Drop for Body {
    fn drop(&mut self) {
        // SAFETY: Body owns this mmap allocation and every entry has returned.
        unsafe { assert_eq!(munmap(self.address, self.len), 0); }
    }
}

/// What a stack probe moved that it must not have: the accumulator and the
/// stack pointer, each as a difference from what the caller set.
#[repr(C)]
#[derive(Default)]
struct ProbeMoved { accumulator: u64, stack: u64 }

/// One scope record, in the order the scope table stores them.
#[derive(Copy, Clone)]
struct Scope { begin: u32, end: u32, handler: u32, jump_target: u32 }

fn scope_table(scopes: &[Scope]) -> Vec<u32> {
    let mut table = vec![scopes.len() as u32];
    for scope in scopes { table.extend_from_slice(&[scope.begin, scope.end, scope.handler, scope.jump_target]); }
    table
}

struct Fixture { record: Vec<u32>, dispatch: Vec<u8>, table: Vec<u32> }

impl Fixture {
    fn new(flags: u32, code: u32, scopes: &[Scope], pc: u64) -> Self {
        let mut fixture = Self { record: vec![code, flags], dispatch: vec![0u8; DISPATCHER_BYTES], table: scope_table(scopes) };
        fixture.put(CONTROL_PC, pc);
        fixture.put(IMAGE_BASE, image_base());
        fixture.put(CONTEXT_RECORD, 0xc0c0_0000);
        fixture.put(HISTORY_TABLE, 0xdddd_0000);
        fixture
    }
    fn put(&mut self, at: usize, value: u64) { self.dispatch[at..at + 8].copy_from_slice(&value.to_le_bytes()); }
    fn put32(&mut self, at: usize, value: u32) { self.dispatch[at..at + 4].copy_from_slice(&value.to_le_bytes()); }
    fn get32(&self, at: usize) -> u32 { u32::from_le_bytes(self.dispatch[at..at + 4].try_into().unwrap()) }
    fn bind(&mut self) { let table = self.table.as_ptr() as u64; self.put(HANDLER_DATA, table); }
    fn enter(&mut self, body: &Body, frame: u64) -> u64 {
        self.bind();
        body.enter(self.record.as_ptr() as u64, frame, 0xcccc_0000, self.dispatch.as_ptr() as u64)
    }
}

fn log() -> [u64; LOG_SLOTS] {
    // SAFETY: the trampolines are the only other writers and none is running.
    unsafe { csh_log }
}
/// The trampolines record into one process-wide log, so a test owns it for
/// the duration of its run rather than racing every other test's calls.
static LOG_OWNED: core::sync::atomic::AtomicBool = core::sync::atomic::AtomicBool::new(false);
struct LogGuard;
impl Drop for LogGuard {
    fn drop(&mut self) { LOG_OWNED.store(false, core::sync::atomic::Ordering::Release); }
}
fn clear_log() -> LogGuard {
    while LOG_OWNED.swap(true, core::sync::atomic::Ordering::Acquire) { core::hint::spin_loop(); }
    // SAFETY: the swap above makes this thread the log's only writer, and the
    // trampolines only run from a handler this thread enters.
    unsafe { csh_log = [0; LOG_SLOTS]; }
    LogGuard
}

/// Scope covering [0x100,0x200) whose filter is `handler` and whose jump
/// target is 0x1000; a scope with no jump target is a termination scope.
fn guarded(handler: u64) -> Scope { Scope { begin: 0x100, end: 0x200, handler: rva(handler), jump_target: 0x1000 } }
fn terminating(handler: u64) -> Scope { Scope { begin: 0x100, end: 0x200, handler: rva(handler), jump_target: 0 } }
/// Control address inside the guarded range above, as the dispatcher reports
/// it: an absolute address over the fixture's image base.
fn control(offset: u64) -> u64 { image_base() + offset }

fn emitted() -> Body { Body::new(&encode_x64_c_specific_handler(address_of(csh_unwind))) }

#[test]
fn the_encoder_binds_the_unwind_entry_and_leaves_no_placeholder() {
    let bound = encode_x64_c_specific_handler(0x1234_5678_9abc_def0);
    assert_eq!(bound.len(), X64_C_SPECIFIC_HANDLER_BYTES);
    let windows: Vec<u64> = bound.windows(8).map(|slot| u64::from_le_bytes(slot.try_into().unwrap())).collect();
    assert!(windows.contains(&0x1234_5678_9abc_def0), "the entry must appear in the body");
    assert!(!windows.contains(&unwind_entry_placeholder()), "the placeholder must be gone");
    // A different entry must move, so the encoder is not returning a constant.
    let other = encode_x64_c_specific_handler(0x0fed_cba9_8765_4321);
    assert_ne!(bound, other);
    let differing = bound.iter().zip(other.iter()).filter(|(a, b)| a != b).count();
    assert_eq!(differing, 8, "only the entry immediate may differ");
}

#[test]
fn a_search_pass_calls_the_filter_with_the_exception_pointers_and_the_frame() {
    let _log = clear_log();
    let body = emitted();
    let mut fixture = Fixture::new(0, 0xc000_0005, &[guarded(address_of(csh_filter_search))], control(0x150));
    let disposition = fixture.enter(&body, 0xf00d_0000);
    assert_eq!(disposition, CONTINUE_SEARCH_DISPOSITION);
    let log = log();
    assert_eq!(log[FILTER_SEARCH], 1, "the filter runs exactly once");
    assert_eq!(log[1], 0xf00d_0000, "the establishing frame is the filter's second argument");
    // The first argument points at the exception pointers: record then context.
    let pointers = log[0] as *const u64;
    // SAFETY: the handler built this pair on its own live frame, which is
    // still mapped; the test only reads the two words it wrote.
    let (record, context) = unsafe { (*pointers, *pointers.add(1)) };
    assert_eq!(record, fixture.record.as_ptr() as u64);
    assert_eq!(context, 0xcccc_0000);
    // Continuing the search leaves the scope index past the whole table.
    assert_eq!(log[FINALLY], 0, "no termination handler runs in a search pass");
}

#[test]
fn a_filter_electing_to_continue_execution_returns_at_once() {
    let _log = clear_log();
    let body = emitted();
    let mut fixture = Fixture::new(0, 0xc000_0005,
        &[guarded(address_of(csh_filter_continue)), guarded(address_of(csh_filter_search))], control(0x150));
    assert_eq!(fixture.enter(&body, 0), CONTINUE_EXECUTION_DISPOSITION);
    let log = log();
    assert_eq!(log[FILTER_CONTINUE], 1, "the deciding filter runs");
    assert_eq!(log[FILTER_SEARCH], 0, "the scope after it is never reached");
    assert_eq!(CONTINUE_EXECUTION, -1);
}

#[test]
fn a_filter_electing_to_run_its_handler_unwinds_to_the_scope_jump_target() {
    let _log = clear_log();
    let body = emitted();
    let mut fixture = Fixture::new(0, 0xc000_0094, &[guarded(address_of(csh_filter_execute))], control(0x150));
    fixture.enter(&body, 0xf00d_0000);
    let log = log();
    assert_eq!(log[UNWIND], 1, "the unwind entry runs once");
    // frame, target, record, code, context record, history table.
    assert_eq!(log[0], 0xf00d_0000);
    assert_eq!(log[1], control(0x1000), "the target is the scope's jump target over the image base");
    assert_eq!(log[2], fixture.record.as_ptr() as u64);
    assert_eq!(log[3], 0xc000_0094, "the exception code is passed as the fourth argument");
    assert_eq!(log[4], 0xc0c0_0000, "the dispatcher's context record is the fifth");
    assert_eq!(log[5], 0xdddd_0000, "its history table is the sixth");
}

#[test]
fn a_scope_asking_to_execute_its_handler_unwinds_without_calling_any_filter() {
    let _log = clear_log();
    let body = emitted();
    let mut fixture = Fixture::new(0, 0xc000_0005,
        &[Scope { begin: 0x100, end: 0x200, handler: EXECUTE_HANDLER, jump_target: 0x2000 }], control(0x150));
    fixture.enter(&body, 0);
    let log = log();
    assert_eq!(log[FILTER_SEARCH] + log[FILTER_EXECUTE] + log[FILTER_CONTINUE], 0, "no filter is entered");
    assert_eq!(log[UNWIND], 1, "the unwind entry runs");
    assert_eq!(log[1], control(0x2000));
}

#[test]
fn a_search_pass_skips_scopes_the_control_address_misses_or_that_terminate() {
    let _log = clear_log();
    let body = emitted();
    let filter = address_of(csh_filter_search);
    let mut fixture = Fixture::new(0, 0, &[
        Scope { begin: 0x000, end: 0x100, handler: rva(filter), jump_target: 0x10 },
        Scope { begin: 0x200, end: 0x300, handler: rva(filter), jump_target: 0x10 },
        terminating(filter),
    ], control(0x150));
    assert_eq!(fixture.enter(&body, 0), CONTINUE_SEARCH_DISPOSITION);
    assert_eq!(log()[FILTER_SEARCH], 0, "the address is outside the first two and the third has no target");
}

#[test]
fn the_range_is_half_open_at_both_ends() {
    let body = emitted();
    let filter = address_of(csh_filter_search);
    for (pc, expected) in [(0x0ff, 0), (0x100, 1), (0x1ff, 1), (0x200, 0)] {
        let _log = clear_log();
        let mut fixture = Fixture::new(0, 0, &[guarded(filter)], control(pc));
        fixture.enter(&body, 0);
        assert_eq!(log()[FILTER_SEARCH], expected, "control address {pc:#x}");
    }
}

#[test]
fn an_unwinding_pass_calls_the_termination_handler_and_advances_the_scope_index() {
    let _log = clear_log();
    let body = emitted();
    let mut fixture = Fixture::new(EXCEPTION_UNWINDING, 0, &[terminating(address_of(csh_finally))], control(0x150));
    assert_eq!(fixture.enter(&body, 0xbeef_0000), CONTINUE_SEARCH_DISPOSITION);
    let log = log();
    assert_eq!(log[FINALLY], 1, "the termination handler runs once");
    assert_eq!(log[0], 1, "it is told this is an abnormal termination");
    assert_eq!(log[1], 0xbeef_0000, "and given the establishing frame");
    // The index was advanced past the scope before the handler was entered, so
    // a re-entry resumes after it rather than repeating it.
    assert_eq!(fixture.get32(SCOPE_INDEX), 1);
}

#[test]
fn an_exit_unwind_takes_the_same_pass_as_an_ordinary_unwind() {
    let _log = clear_log();
    let body = emitted();
    let mut fixture = Fixture::new(EXCEPTION_EXIT_UNWIND, 0, &[terminating(address_of(csh_finally))], control(0x150));
    fixture.enter(&body, 0);
    assert_eq!(log()[FINALLY], 1);
}

#[test]
fn an_unwinding_pass_ignores_scopes_that_name_a_jump_target() {
    let _log = clear_log();
    let body = emitted();
    let mut fixture = Fixture::new(EXCEPTION_UNWINDING, 0, &[guarded(address_of(csh_finally))], control(0x150));
    fixture.enter(&body, 0);
    assert_eq!(log()[FINALLY], 0, "a guarded scope has no termination handler to run");
}

#[test]
fn a_target_unwind_stops_at_the_scope_holding_the_target_without_entering_it() {
    let _log = clear_log();
    let body = emitted();
    let mut fixture = Fixture::new(EXCEPTION_UNWINDING | EXCEPTION_TARGET_UNWIND, 0,
        &[terminating(address_of(csh_finally)), terminating(address_of(csh_finally))], control(0x150));
    fixture.put(TARGET_IP, control(0x180));
    assert_eq!(fixture.enter(&body, 0), CONTINUE_SEARCH_DISPOSITION);
    assert_eq!(log()[FINALLY], 0, "the pass breaks at the target's own scope");
    // A target outside the scope leaves the handler to run, which is what
    // makes the check above a real one rather than an always-taken branch.
    drop(_log);
    let _log = clear_log();
    let mut past = Fixture::new(EXCEPTION_UNWINDING | EXCEPTION_TARGET_UNWIND, 0,
        &[terminating(address_of(csh_finally))], control(0x150));
    past.put(TARGET_IP, control(0x900));
    past.enter(&body, 0);
    assert_eq!(log()[FINALLY], 1);
}

#[test]
fn a_pass_resumes_at_the_scope_index_it_is_handed() {
    let _log = clear_log();
    let body = emitted();
    let mut fixture = Fixture::new(EXCEPTION_UNWINDING, 0,
        &[terminating(address_of(csh_finally)), terminating(address_of(csh_finally))], control(0x150));
    fixture.put32(SCOPE_INDEX, 1);
    fixture.enter(&body, 0);
    assert_eq!(log()[FINALLY], 1, "only the scope at and after the index runs");
    assert_eq!(fixture.get32(SCOPE_INDEX), 2);
}

#[test]
fn an_empty_scope_table_continues_the_search_in_both_passes() {
    for flags in [0, EXCEPTION_UNWINDING] {
        let _log = clear_log();
        let body = emitted();
        let mut fixture = Fixture::new(flags, 0, &[], control(0x150));
        assert_eq!(fixture.enter(&body, 0), CONTINUE_SEARCH_DISPOSITION);
        assert_eq!(log()[FILTER_SEARCH] + log()[FINALLY] + log()[UNWIND], 0);
    }
}

#[test]
fn the_stack_probe_is_a_single_return_that_changes_nothing() {
    assert_eq!(X64_RET_STUB_BYTES, 1);
    assert_eq!(encode_x64_ret_stub(), [0xc3]);
    let body = Body::new(&encode_x64_ret_stub());
    // The compiler's probe sequence loads the frame size into the accumulator,
    // calls the probe, then subtracts the accumulator from the stack pointer.
    // The probe must therefore return with the accumulator and the stack
    // pointer exactly as it found them.
    for size in [0x1000u64, 0x1_0000, 0xffff_ffff] {
        let mut moved = ProbeMoved::default();
        // SAFETY: the mapping holds the emitted probe; the trampoline enters
        // it with the accumulator loaded and writes the differences here.
        unsafe { csh_probe_call(body.address.cast(), size, &mut moved); }
        assert_eq!(moved.accumulator, 0, "the probe must leave the accumulator alone");
        assert_eq!(moved.stack, 0, "and the stack pointer where its return found it");
    }
}
