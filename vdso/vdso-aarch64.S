// vDSO entry points for aarch64.
//
// Layout of the kernel-published vvar page at `_vdso_data` mirrors
// the x86_64 vDSO:
//   off  0  u32 seq
//   off  4  u32 _pad
//   off  8  u64 monotonic_ns
//   off 16  u64 realtime_sec
//   off 24  u64 realtime_nsec
//
// __kernel_clock_gettime fast path for CLOCK_MONOTONIC/REALTIME
// reads the vvar via a seqlock loop. Other clocks fall back to svc.
// arm64 syscall ABI: nr in x8; args in x0..x5; ret in x0.

.section .text
.balign 16

.global __kernel_clock_gettime
.type __kernel_clock_gettime, %function
__kernel_clock_gettime:
    cbz     x1, .Lct_syscall_arm
    cmp     w0, #1                    // CLOCK_MONOTONIC?
    beq     .Lct_mono_arm
    cmp     w0, #0                    // CLOCK_REALTIME?
    beq     .Lct_real_arm
.Lct_syscall_arm:
    mov     x8, #113                  // NR_clock_gettime
    svc     #0
    ret

    // load address of _vdso_data into x4 once per attempt using ADR
    // (PIC, ±1 MiB). The linker-script PROVIDE places _vdso_data at
    // base - 0x1000; ADR resolves the right runtime address.
.Lct_mono_arm:
1:  adrp    x4, _vdso_data
    add     x4, x4, #:lo12:_vdso_data
    ldr     w5, [x4, #0]              // seq
    tbnz    w5, #0, 1b
    ldr     x2, [x4, #8]              // monotonic_ns
    dmb     ish                       // ensure seq re-read after data
    ldr     w6, [x4, #0]
    cmp     w5, w6
    b.ne    1b
    // ts->tv_sec  = ns / 1_000_000_000
    // ts->tv_nsec = ns % 1_000_000_000
    movz    x3, #0xCA00
    movk    x3, #0x3B9A, lsl #16        // 1_000_000_000 (CA00 + 3B9A0000)
    udiv    x6, x2, x3
    msub    x7, x6, x3, x2
    str     x6, [x1, #0]
    str     x7, [x1, #8]
    mov     w0, #0
    ret

.Lct_real_arm:
1:  adrp    x4, _vdso_data
    add     x4, x4, #:lo12:_vdso_data
    ldr     w5, [x4, #0]
    tbnz    w5, #0, 1b
    ldr     x2, [x4, #16]             // realtime_sec
    ldr     x3, [x4, #24]             // realtime_nsec
    dmb     ish
    ldr     w6, [x4, #0]
    cmp     w5, w6
    b.ne    1b
    str     x2, [x1, #0]
    str     x3, [x1, #8]
    mov     w0, #0
    ret
.size __kernel_clock_gettime, .-__kernel_clock_gettime

.global clock_gettime
.type clock_gettime, %function
clock_gettime: b __kernel_clock_gettime
.size clock_gettime, .-clock_gettime

.global __kernel_gettimeofday
.type __kernel_gettimeofday, %function
__kernel_gettimeofday:
    mov     x8, #169
    svc     #0
    ret
.size __kernel_gettimeofday, .-__kernel_gettimeofday

.global gettimeofday
.type gettimeofday, %function
gettimeofday: b __kernel_gettimeofday
.size gettimeofday, .-gettimeofday

.global __kernel_getcpu
.type __kernel_getcpu, %function
__kernel_getcpu:
    mov     x8, #168
    svc     #0
    ret
.size __kernel_getcpu, .-__kernel_getcpu

.global __kernel_clock_getres
.type __kernel_clock_getres, %function
__kernel_clock_getres:
    mov     x8, #114
    svc     #0
    ret
.size __kernel_clock_getres, .-__kernel_clock_getres

.global __kernel_rt_sigreturn
.type __kernel_rt_sigreturn, %function
__kernel_rt_sigreturn:
    mov     x8, #139
    svc     #0
    ret
.size __kernel_rt_sigreturn, .-__kernel_rt_sigreturn

.section .note.GNU-stack,"",%progbits
