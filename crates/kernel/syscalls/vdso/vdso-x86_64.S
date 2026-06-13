// vDSO entry points for x86_64.
//
// Layout of the kernel-published vvar page at `_vdso_data`:
//   off  0  u32 seq            // seqlock (even = stable)
//   off  4  u32 tsc_khz        // counter freq → compute monotonic LIVE
//   off  8  u64 realtime_sec   // CLOCK_REALTIME wall sec (coarse snapshot)
//   off 16  u64 realtime_nsec  // wall nsec
//
// CLOCK_MONOTONIC is computed LIVE from `rdtsc` + `tsc_khz`
// (ns = TSC * 1e6 / tsc_khz, matching the kernel's monotonic_ns) — no
// snapshot, so no staleness/jumps that broke userspace deadline math.
// CLOCK_REALTIME reads the coarse snapshot via a seqlock loop. Other
// clocks fall back to the syscall.

.section .text
.balign 16

// __vdso_clock_gettime(clockid_t clk_id, struct timespec *ts)
//   rdi = clk_id; rsi = ts
.global __vdso_clock_gettime
.type __vdso_clock_gettime, @function
__vdso_clock_gettime:
    test    %rsi, %rsi
    jz      .Lct_syscall
    cmp     $1, %edi                    // CLOCK_MONOTONIC?
    je      .Lct_mono
    cmp     $0, %edi                    // CLOCK_REALTIME?
    je      .Lct_real
.Lct_syscall:
    mov     $228, %eax                  // NR_CLOCK_GETTIME
    syscall
    ret

.Lct_mono:
    // LIVE: ns = rdtsc() * 1_000_000 / tsc_khz (matches kernel HAL).
    mov     _vdso_data+4(%rip), %ecx    // tsc_khz (u32, zero-extended)
    test    %ecx, %ecx
    jz      .Lct_syscall                // not yet published → syscall
    rdtsc                               // edx:eax = TSC hi:lo (uppers zeroed)
    shl     $32, %rdx
    or      %rdx, %rax                  // rax = full 64-bit TSC
    mov     $1000000, %rdi
    mul     %rdi                        // rdx:rax = TSC * 1e6 (128-bit)
    div     %rcx                        // rax = ns, rdx = remainder
    // ts->tv_sec = ns / 1e9 ; ts->tv_nsec = ns % 1e9
    mov     $1000000000, %rcx
    xor     %edx, %edx
    div     %rcx
    mov     %rax, 0(%rsi)
    mov     %rdx, 8(%rsi)
    xor     %eax, %eax
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

.global clock_gettime
.type clock_gettime, @function
clock_gettime: jmp __vdso_clock_gettime
.size clock_gettime, .-clock_gettime

.global __vdso_gettimeofday
.type __vdso_gettimeofday, @function
__vdso_gettimeofday:
    mov     $96, %eax
    syscall
    ret
.size __vdso_gettimeofday, .-__vdso_gettimeofday

.global gettimeofday
.type gettimeofday, @function
gettimeofday: jmp __vdso_gettimeofday
.size gettimeofday, .-gettimeofday

.global __vdso_time
.type __vdso_time, @function
__vdso_time:
    mov     $201, %eax
    syscall
    ret
.size __vdso_time, .-__vdso_time

.global time
.type time, @function
time: jmp __vdso_time
.size time, .-time

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
