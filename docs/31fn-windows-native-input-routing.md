# Windows native input routing

FROZEN 2026-09-01. Dep:`28`,`31t`,`31u`,`31fl`,`52`,`53`. Provides: physical keyboard delivery from the canonical Linux input owner to the foreground NT window queue.

## 1 Contract

- The Linux input registry remains the sole owner of physical `EV_KEY` acceptance, key state, and device lifetime.
- The registry exposes one optional native-key sink; unset means no NT delivery and preserves existing Linux input behavior.
- The NT window service installs the sink when an NT window call first reaches the kernel and selects the process whose window has focus as the foreground input owner.
- A foreground key transition is delivered to the focused HWND owner queue as `WM_KEYDOWN` or `WM_KEYUP`; queue overflow is reported and never silently drops the transition.
- System keyboard controls owned by Linux input, including VT switching and Ctrl-Alt-Delete policy, remain evaluated before ordinary foreground-window delivery.
- A foreground NT key transition is consumed by the native route after those system controls, so it is not duplicated into the Linux controlling terminal.
- When no foreground NT window exists, the existing Linux keymap and controlling-terminal path receives the event unchanged.

## 2 Ownership

- `input` owns the optional callback contract and invokes it after physical-event acceptance.
- `drv-virtio-input` owns transport drain and preserves the Linux system-key ladder.
- `syscalls::nt_window` owns foreground selection, focused-window lookup, queue insertion, and waiter wakeup.
- Window state remains in the canonical IPC `WindowManager`; no input-side HWND table is permitted.

## 3 Tests

- accepted key transitions reach the native sink with press/release state;
- no installed sink preserves the Linux-only path;
- focused-window routing preserves HWND, key code, press/release, and repeat state;
- no-focus and queue-full cases do not report successful native delivery;
- foreground native delivery and Linux fallback are covered by the normal Windows compatibility suite;
- x86_64 and aarch64 kernel builds remain green, while only x86_64 carries the Windows runtime workload.
