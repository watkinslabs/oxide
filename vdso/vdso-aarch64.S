// vDSO entry points for aarch64. Each does the equivalent svc 0
// syscall. Linux generic-arm64 syscall numbers (clock_gettime=113,
// gettimeofday=169, getcpu=168, clock_getres=114). aarch64 has no
// distinct `time` syscall — glibc emulates via clock_gettime.

.section .text
.balign 16

.global __kernel_clock_gettime
.type __kernel_clock_gettime, %function
__kernel_clock_gettime:
    mov x8, #113       // NR_clock_gettime (arm64 generic)
    svc #0
    ret
.size __kernel_clock_gettime, .-__kernel_clock_gettime

.global clock_gettime
.type clock_gettime, %function
clock_gettime: b __kernel_clock_gettime
.size clock_gettime, .-clock_gettime

.global __kernel_gettimeofday
.type __kernel_gettimeofday, %function
__kernel_gettimeofday:
    mov x8, #169       // NR_gettimeofday
    svc #0
    ret
.size __kernel_gettimeofday, .-__kernel_gettimeofday

.global gettimeofday
.type gettimeofday, %function
gettimeofday: b __kernel_gettimeofday
.size gettimeofday, .-gettimeofday

.global __kernel_getcpu
.type __kernel_getcpu, %function
__kernel_getcpu:
    mov x8, #168       // NR_getcpu
    svc #0
    ret
.size __kernel_getcpu, .-__kernel_getcpu

.global __kernel_clock_getres
.type __kernel_clock_getres, %function
__kernel_clock_getres:
    mov x8, #114       // NR_clock_getres
    svc #0
    ret
.size __kernel_clock_getres, .-__kernel_clock_getres

.global __kernel_rt_sigreturn
.type __kernel_rt_sigreturn, %function
__kernel_rt_sigreturn:
    mov x8, #139       // NR_rt_sigreturn
    svc #0
    ret
.size __kernel_rt_sigreturn, .-__kernel_rt_sigreturn

.section .note.GNU-stack,"",%progbits
