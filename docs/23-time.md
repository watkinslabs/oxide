# 23 Time

FROZEN 2026-05-02. Dep:`01`,`02`,`06`,`07`,`14`,`20`,`21`,`22`. Provides:`13`,`15`,`24` (timerfd),`30` (io_uring timeouts), every driver.
## 1 Purpose

Monotonic clock, wall clock, oneshot timers per-CPU, NTP slewing, vDSO time. Backed by TSC-deadline (x86) / Generic Timer (arm).

## 2 Invariants (frozen)

1. `Nanos::now()` non-decreasing per CPU and globally (across CPUs after sync).
2. CLOCK_MONOTONIC strictly non-decreasing across the system; resolution ≤ 100 ns.
3. CLOCK_REALTIME may jump on `clock_settime` or NTP step; otherwise tracks wall.
4. vDSO time data: seqlock protocol; readers retry on writer-in-progress.
5. Timer expiry order: a timer with deadline `d1 < d2` fires before `d2` (within IRQ-latency).
6. Per-CPU oneshot deadline programmed iff there exists a pending timer ≤ `now + max_idle_horizon`.

## 3 Public ifc

```rust
pub fn now() -> Nanos;
pub fn realtime() -> Wallclock;
pub fn sleep(d: Duration);                                      // Sleeps:y
pub fn sleep_until(deadline: Nanos);

pub struct HrTimer { /* per-cpu, intrusive */ }
impl HrTimer {
    pub fn new(deadline:Nanos, cb:fn(*mut HrTimer), cpu:CpuId) -> Self;
    pub fn arm(&mut self);
    pub fn cancel(&mut self) -> bool;
}

// Syscalls in 15:
// 35 nanosleep, 230 clock_nanosleep, 222-226 timer_create/set/get/delete,
// 227 clock_settime, 228 clock_gettime, 229 clock_getres, 305 clock_adjtime
// 283 timerfd_create, 286 timerfd_settime, 287 timerfd_gettime
```

## 4 Hardware sources

x86_64:
- TSC: invariant TSC mandatory (per `03§7`). `rdtsc` ordered with `lfence` before for read.
- TSC frequency from CPUID 15h or MSR `MSR_PLATFORM_INFO`/calibration.
- TSC-deadline mode for per-CPU oneshot.
- HPET: discovery sanity check only; not used as runtime source.

aarch64:
- CNTVCT_EL0: virtual count register.
- CNTFRQ_EL0: frequency.
- Per-CPU timer via CNTP_TVAL_EL0 / CNTP_CTL_EL0.

## 5 Boot calibration

1. Read TSC/CNTVCT @ start.
2. Wait via PIT (x86) or TZ-fallback for 50 ms.
3. Read again. Compute frequency.
4. Verify against firmware-claimed frequency (CPUID 15h / CNTFRQ); divergence >1% ⇒ kassert (likely VM weirdness; fall back to firmware value).
5. Store `freq_khz`,`scale`,`shift` for `cycles_to_ns` math.

## 6 Read path

```
cycles_to_ns(c) = (c * scale) >> shift
now() = cycles_to_ns(rdtsc()) - offset_ns
```

`offset_ns` set at boot so `now()` starts near 0.

vDSO does the same math from `vvar` page (see §9).

## 7 Wall clock

Stored as `wall_offset_ns` (CLOCK_REALTIME = CLOCK_MONOTONIC + offset). Adjusted by `clock_settime`/NTP. Slewing handled by adjusting `(scale,shift)` slowly via `clock_adjtime`.

Initial seed:
- UEFI: `Time` runtime service if available.
- Else RTC (CMOS on x86, PL031 on arm) read once.
- Else 0; userspace `chronyd` will set later.

## 8 Timers

Per-CPU red-black tree of `HrTimer` keyed by deadline. Earliest-deadline programmed into TSC-deadline / CNTP_CVAL.

ISR:
```
on timer_irq():
  while rb.peek().deadline <= now():
    t = rb.pop()
    t.cb(t)              # may rearm
  reprogram(rb.peek().deadline)
```

Cross-CPU: timer always fires on the CPU where armed. Migrate via cancel+rearm.

## 9 vDSO time data

`vvar` page (one per system, read-only mapped into every AS):

```rust
#[repr(C, align(64))]
struct Vvar {
    seq: AtomicU32,
    clock_mode: u32,         // 0=tsc, 1=cntvct, 2=fallback-syscall
    cycle_last: u64,
    mult: u64, shift: u32,
    offset_mono_ns: u64,
    offset_real_ns: u64,
    raw_freq_khz: u32,
    pad: [u8; ...],          // 64-byte alignment
}
```

Update path (kernel, in tick ISR):
1. `seq.store(seq+1, Release)` (odd → in progress).
2. Update fields.
3. `seq.store(seq+2, Release)` (even → done).

Read path (userspace vDSO):
1. Loop: `s = seq.load(Acquire); if s&1: pause; continue;`
2. Read fields (Acquire).
3. Re-read `seq.load(Acquire); if != s: retry;`
4. Compute `now_ns`.

## 10 Concurrency

- Per-CPU timer rb: spinlock class `Timer` (low rank).
- vvar update: seqlock; only timer-tick writes; reads lockless.
- Wall offset: single seqlock (global).
- NTP slew: protected by `clock_lock` (Spinlock, class `Timer`).

## 11 Perf budget

| Op | p99 |
|---|---|
| `now()` kernel call | ≤ 20 cy |
| `clock_gettime(MONOTONIC)` via vDSO | ≤ 30 cy (1 rdtsc + math + seq retry) |
| `clock_gettime` syscall fallback | ≤ 800 cy |
| Timer arm | ≤ 250 cy |
| Timer fire→cb | ≤ 400 cy |

## 12 Test contract (frozen)

- Monotonicity: 64-thread parallel `now()` for 60s; assert strictly non-decreasing per thread, no thread sees a clock more than 1ms behind another.
- Resolution: `clock_getres(MONOTONIC) ≤ 100 ns`.
- vDSO consistency: 10M reads while kernel updates vvar; assert no torn read (seq retry catches all).
- Timer accuracy: arm 100K timers with random deadlines; p99 deadline overshoot ≤ 50 µs.
- NTP slew: simulate 1000 ppm drift; verify slew converges within 5 minutes.
- Wall clock: `clock_settime(REALTIME)` jumps; MONOTONIC unaffected.
- Coverage ≥90%.

## 13 Failure modes

- TSC unstable (frequency change detected via consistency check between cores): kassert if invariant TSC was claimed; fall back to syscall-only path otherwise (no vDSO).
- Calibration mismatch >1%: kassert.
- Timer rb invariant broken: kassert.

## 14 Debug

`debug-time`: log every timer fire/cancel; vvar update audit; cross-CPU clock skew sampler.

## 15 Cross-spec

`13` (timer_tick drives sched), `15` (clock/timer syscalls), `22` (timer ISR), `30` (io_uring timeouts via HrTimer), `24` (timerfd is HrTimer + eventfd).

