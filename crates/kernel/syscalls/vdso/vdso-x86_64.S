// vDSO entry points for x86_64.
//
// Layout of the kernel-published vvar page at `_vdso_data`:
//   off  0  u32 seq            // seqlock (even = stable)
//   off  4  u32 tsc_khz        // counter freq → compute monotonic LIVE
//   off  8  u64 realtime_sec   // CLOCK_REALTIME wall sec (coarse snapshot)
//   off 16  u64 realtime_nsec  // wall nsec
//
// CLOCK_REALTIME reads the coarse snapshot via a seqlock loop. Namespace-
// relative clocks fall back to the syscall because the shared vvar page is
// not a per-time-namespace offset page.

.section .text
.balign 16

// __vdso_clock_gettime(clockid_t clk_id, struct timespec *ts)
//   rdi = clk_id; rsi = ts
.global __vdso_clock_gettime
.type __vdso_clock_gettime, @function
__vdso_clock_gettime:
    test    %rsi, %rsi
    jz      .Lct_syscall
    cmp     $0, %edi                    // CLOCK_REALTIME?
    je      .Lct_real
.Lct_syscall:
    mov     $228, %eax                  // NR_CLOCK_GETTIME
    syscall
    ret

.Lct_real:
1:  mov     _vdso_data+0(%rip), %r8d
    test    $1, %r8d
    jnz     1b
    mov     _vdso_data+8(%rip), %rax    // realtime_sec
    mov     _vdso_data+16(%rip), %rcx   // realtime_nsec
    lfence
    mov     _vdso_data+0(%rip), %r9d
    cmp     %r8d, %r9d
    jne     1b
    mov     %rax, 0(%rsi)
    mov     %rcx, 8(%rsi)
    xor     %eax, %eax
    ret
.size __vdso_clock_gettime, .-__vdso_clock_gettime

.global __vdso_gettimeofday
.type __vdso_gettimeofday, @function
__vdso_gettimeofday:
    mov     $96, %eax
    syscall
    ret
.size __vdso_gettimeofday, .-__vdso_gettimeofday

.global __vdso_time
.type __vdso_time, @function
__vdso_time:
    mov     $201, %eax
    syscall
    ret
.size __vdso_time, .-__vdso_time

.global __vdso_getcpu
.type __vdso_getcpu, @function
__vdso_getcpu:
    mov     $309, %eax
    syscall
    ret
.size __vdso_getcpu, .-__vdso_getcpu

.global __vdso_clock_getres
.type __vdso_clock_getres, @function
__vdso_clock_getres:
    mov     $229, %eax
    syscall
    ret
.size __vdso_clock_getres, .-__vdso_clock_getres

.section .note.GNU-stack,"",@progbits
