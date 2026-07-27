/* wait_diff — interruptible-wait / restart-semantics Linux differential probe.
 *
 * Same shape as userspace/af_packet_diff: every case prints ONE
 * `wdiff|<area>|<test>|k=v|...` record. The identical binary runs on the
 * host Linux kernel (the ORACLE) and inside the oxide guest; the records
 * must match byte-for-byte (tools/boot-smoke-wait-diff.sh diffs them).
 *
 * Determinism rule: never print a raw duration, pointer, pid or errno
 * number that the two kernels may legitimately disagree about for reasons
 * unrelated to the semantics under test. Print BUCKETS
 * (`rem_lt_req=1`) and named errnos instead.
 *
 * Glibc-vs-raw-syscall rule: the sleep family goes through
 * `syscall(SYS_clock_nanosleep, ...)` because glibc's `clock_nanosleep`
 * wrapper RETURNS the errno instead of setting it, and its `nanosleep`
 * wrapper is itself a `clock_nanosleep(CLOCK_REALTIME, 0, ...)` shim on
 * both arches — going raw makes the two arches and the two kernels
 * observe the same ABI. Everything else uses the ordinary glibc entry
 * point, which IS the interface under test for those calls.
 */
#ifndef WAIT_DIFF_PROBE_H
#define WAIT_DIFF_PROBE_H

#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <mqueue.h>
#include <netinet/in.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <termios.h>
#include <time.h>
#include <unistd.h>

/* Milliseconds. The signal always lands well inside the wait; the wait's
 * own release always lands well after the signal, so "restarted" and
 * "failed with EINTR" are separated by ~450ms of slack on both kernels. */
/* The signal must land WELL inside every wait. B1449 proved the old 4x
 * margin was not enough: on a loaded/TCG guest the peer's write beat the
 * itimer, the recv returned its payload, the signal was delivered at the
 * syscall tail (so `sig=1` STILL held) and the record read as a PASS for a
 * kernel that could not restart at all. A record that can go green for the
 * wrong reason is worse than no record. 10x margin now. */
/* B1453: the SLEEP family kept the 4x margin C229 had just proved
 * insufficient, and it fails the same way. On aarch64 the 600 ms sleep
 * reached its own expiry before the 150 ms itimer's SIGALRM reached the
 * PARKED sleeper, so the "expiry already passed" arm returned rc=0 with rmtp
 * untouched and the handler ran at the syscall tail — `sig=1` still held, so
 * the record looked like a semantics failure. Linux does exactly the same
 * under that latency (`kernel/time/hrtimer.c:2408` `if (!t->task) return 0;`
 * precedes the `signal_pending` test), so the row was measuring guest wake
 * latency, not sleep semantics. Same 10x margin as RELEASE_MS. CONT_MS must
 * stay > SLEEP_MS: stop/cont needs the expiry to pass WHILE stopped. */
#define SIG_DELAY_MS     150u
#define RELEASE_MS      1500u
#define SLEEP_MS        1500u
#define STOP_MS          150u
#define CONT_MS         2500u
#define KILL_DELAY_MS    400u
#define CPU_SLEEP_MS     300u
#define CPU_GUARD_MS     900u
#define CPU_BURN_GUARD_MS 5000u
#define JOBCTL_GUARD_S   10u
#define MQ_ABS_TIMEOUT_S 30

/* Sentinel written into every `rem` buffer before a sleep, so "the kernel
 * did not touch rem" is observable rather than inferred from a zero. */
#define REM_SENTINEL_SEC  987654321L
#define REM_SENTINEL_NSEC 123456789L

extern volatile sig_atomic_t g_sig_count;

void out(const char *area, const char *test, const char *fmt, ...)
    __attribute__((format(printf, 3, 4)));
const char *errno_name(int err);

/* Uninterruptible helper sleep — resumes across its own EINTR so a probe's
 * scaffolding can never be the thing that reports an interruption. */
void sleep_ms(unsigned ms);
long long mono_ms(void);

/* SA_RESTART iff `restart` and the `eintr` mutant is not active. Resets
 * g_sig_count. */
int  install_handler(int sig, int restart);
void arm_timer_ms(unsigned ms);
void disarm_timer(void);

/* WAIT_DIFF_MUTANT=<name> — deliberate breakage used by
 * tools/wait-diff-selftest.sh to prove each probe can fail. */
int  mutant(const char *name);

/* Fork a child that sleeps `delay_ms`, writes `len` bytes of 'x' to `fd`,
 * then _exits. Caller closes its own copy of `fd`. */
pid_t spawn_writer(int fd, unsigned delay_ms, size_t len);
void  reap(pid_t pid);
void  wr1(int fd, char c);

/* Reap `pid` within `ms`; 0 means it is still parked. Every case whose
 * failure mode is "never returns" runs in a child behind this, so a stall
 * becomes the record `outcome=blocked` instead of eating the whole run —
 * a hung probe collects no evidence about the 28 cases behind it. */
int wait_bounded(pid_t pid, unsigned ms, int *st);
#define BLOCKED_GUARD_MS 5000u

/* Shared outcome classification, so a child can hand a result back
 * through an exit code without inventing a per-file encoding. */
#define CLS_OK         0
#define CLS_EINTR      1
#define CLS_ENOSYS     2
#define CLS_EOPNOTSUPP 3
#define CLS_EINVAL     4
#define CLS_OTHER      5
int         err_class(int rc, int err);
const char *err_class_name(int cls);

/* Raw clock_nanosleep — see the header comment for why. */
int raw_clock_nanosleep(clockid_t clk, int flags,
                        const struct timespec *req, struct timespec *rem);

void probe_sleep(void);
void probe_locks(void);
void probe_fdwait(void);
void probe_jobctl(void);
void probe_cputime(void);
void probe_mqueue(void);
void probe_syslog(void);

#endif
