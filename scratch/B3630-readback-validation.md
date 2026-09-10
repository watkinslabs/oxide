# X-server frame observation

Status: implemented; runtime stripe diagnosis open. Branch: B3630-paint-region-collapse. Owner: KI-0860.

- Actual accepted Frame path calls `Backend::observe_frame` after successful repaint. Explicit `OXIDE_COMPOSITOR_READBACK=1` enables GetImage comparison against retained damage plus caret overlay. Default disabled; no drawing/ACK changes.
- Harness `OXIDE_NOTEPAD_READBACK=1` adds compositor environment to desktop session launch after session credentials/environment adoption. Wrapper and runtime child preserve it.
- Four real-X-server tests cover actual hook, mapped child drawable coverage, independent one-pixel server overwrite and unavailable coverage/drawables. Child test reads every child pixel after parent full/partial frames.
- Hook removal fails observation count (exit101), launch flag removal fails Python wiring check (exit1), missing UART finding fails mismatch fixture (exit1). Logs `/tmp/B3630-readback-{hook,launch,audit}-red.log`.
- Full compositor suite:107 tests,0 failed; `/tmp/B3630-readback-complete.log`. Notepad Python suite:54 tests,0 failed; `/tmp/B3630-readback-python-final.log`.
- Both userspace release builds pass: `/tmp/B3630-readback-build-x86.log`, `/tmp/B3630-readback-build-arm-corrected.log`. Initial ARM invocation omitted existing sysroot GCC library search directory and failed `-lgcc_s`; corrected invocation adds sysroot `usr/lib/gcc/aarch64-redhat-linux/15` to native search. No sysroot files changed.
- Readback measures X drawable state at the frame only. Occlusion, later desktop composition and physical scanout remain distinct; unavailable reads never become matches. No new VM run; retained Sept10 About stripes remain unexplained.
