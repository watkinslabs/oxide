// vDSO entry points for x86_64. Each function does the equivalent
// syscall via the `syscall` instruction. v1 has no vvar-page fast
// path — the symbols exist so glibc/musl/Go's AT_SYSINFO_EHDR
// probe succeeds and the runtime gets a vDSO-shaped indirection.
// Fast-path optimization (read monotonic_ns from a kernel-mapped
// shared page without leaving user mode) is a follow-up that adds
// the vvar page + a clock-monotonic encoder in the kernel.
//
// SysV-AMD64 syscall ABI: nr in rax; args in rdi/rsi/rdx/r10/r8/r9;
// ret in rax. The `syscall` instruction clobbers rcx (saves rip)
// and r11 (saves rflags) — both caller-saved so no problem.

.section .text
.balign 16

.global __vdso_clock_gettime
.type __vdso_clock_gettime, @function
__vdso_clock_gettime:
    mov $228, %rax     // NR_CLOCK_GETTIME
    syscall
    ret
.size __vdso_clock_gettime, .-__vdso_clock_gettime

.global clock_gettime
.type clock_gettime, @function
clock_gettime: jmp __vdso_clock_gettime
.size clock_gettime, .-clock_gettime

.global __vdso_gettimeofday
.type __vdso_gettimeofday, @function
__vdso_gettimeofday:
    mov $96, %rax      // NR_GETTIMEOFDAY
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
    mov $201, %rax     // NR_TIME
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
    mov $309, %rax     // NR_GETCPU
    syscall
    ret
.size __vdso_getcpu, .-__vdso_getcpu

.global __vdso_clock_getres
.type __vdso_clock_getres, @function
__vdso_clock_getres:
    mov $229, %rax     // NR_CLOCK_GETRES
    syscall
    ret
.size __vdso_clock_getres, .-__vdso_clock_getres

.section .note.GNU-stack,"",@progbits
