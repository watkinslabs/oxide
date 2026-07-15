// vDSO entry points for aarch64.
//
// Layout of the kernel-published vvar page at `_vdso_data` mirrors
// the x86_64 vDSO:
//   off  0  u32 seq
//   off  4  u32 tsc_khz        // CNTFRQ in kHz → compute monotonic LIVE
//   off  8  u64 realtime_sec
//   off 16  u64 realtime_nsec
//
// CLOCK_REALTIME reads the coarse snapshot via a seqlock loop. Namespace-
// relative clocks fall back to svc because the shared vvar page is not a
// per-time-namespace offset page.
// arm64 syscall ABI: nr in x8; args in x0..x5; ret in x0.

.section .text
.balign 16

.global __kernel_clock_gettime
.type __kernel_clock_gettime, %function
__kernel_clock_gettime:
    cbz     x1, .Lct_syscall_arm
    cmp     w0, #0                    // CLOCK_REALTIME?
    beq     .Lct_real_arm
.Lct_syscall_arm:
    mov     x8, #113                  // NR_clock_gettime
    svc     #0
    ret

.Lct_real_arm:
1:  adrp    x4, _vdso_data
    add     x4, x4, #:lo12:_vdso_data
    ldr     w5, [x4, #0]
    tbnz    w5, #0, 1b
    ldr     x2, [x4, #8]             // realtime_sec
    ldr     x3, [x4, #16]            // realtime_nsec
    dmb     ish
    ldr     w6, [x4, #0]
    cmp     w5, w6
    b.ne    1b
    str     x2, [x1, #0]
    str     x3, [x1, #8]
    mov     w0, #0
    ret
.size __kernel_clock_gettime, .-__kernel_clock_gettime

.global __kernel_gettimeofday
.type __kernel_gettimeofday, %function
__kernel_gettimeofday:
    mov     x8, #169
    svc     #0
    ret
.size __kernel_gettimeofday, .-__kernel_gettimeofday

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
