// vDSO entry points for x86_64.
//
// Layout of the kernel-published vvar page at `_vdso_data`:
//   off  0  u32 seq            // seqlock (even = stable)
//   off  4  u32 _pad
//   off  8  u64 monotonic_ns   // kernel's latest CLOCK_MONOTONIC
//   off 16  u64 realtime_sec   // kernel's latest CLOCK_REALTIME wall sec
//   off 24  u64 realtime_nsec  // wall nsec
//
// __vdso_clock_gettime fast path: CLOCK_MONOTONIC and CLOCK_REALTIME
// read vvar via a seqlock loop, no syscall. Other clocks fall back.

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
    // seqlock retry loop
1:  mov     _vdso_data+0(%rip), %r8d    // seq
    test    $1, %r8d
    jnz     1b
    mov     _vdso_data+8(%rip), %rax    // monotonic_ns
    lfence                              // ensure seq re-read after data
    mov     _vdso_data+0(%rip), %r9d
    cmp     %r8d, %r9d
    jne     1b
    // ts->tv_sec  = ns / 1_000_000_000
    // ts->tv_nsec = ns % 1_000_000_000
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
    mov     _vdso_data+16(%rip), %rax   // realtime_sec
    mov     _vdso_data+24(%rip), %rcx   // realtime_nsec
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
