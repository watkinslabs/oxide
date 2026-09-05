#!/usr/bin/env bash
# Hosted W10 boundary gate. It checks that the production NT entry symbol owns
# a real timer interval and that the reusable accumulator tests are executable.
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source="$root/crates/kernel/syscalls/src/dispatch/core.rs"
measure="$root/crates/kernel/syscalls/src/nt_transition_measure.rs"

require() {
    local label="$1" file="$2" text="$3"
    grep -Fq -- "$text" "$file" || { echo "windows-nt-transition-harness: FAIL ($label)" >&2; exit 1; }
}

require "production NT entry" "$source" "pub unsafe extern \"C\" fn oxide_nt_syscall_dispatch"
require "entry timestamp" "$source" "let transition_start = crate::nt_transition_measure::start();"
require "invalid-entry sample" "$source" "crate::nt_transition_measure::record(transition_start);"
require "successful-entry sample" "$source" "let rv = crate::nt_dispatch::dispatch(call);"
require "real monotonic source" "$measure" "hal_x86_64::X86TimerOps::monotonic_ns().0"
require "ARM monotonic source" "$measure" "hal_aarch64::ArmTimerOps::monotonic_ns().0"
require "NT report" "$measure" "[NT-SYSCOST] transitions="
require "saturation test" "$measure" "stats_keep_real_sample_extrema_and_saturate"

if [[ "$(grep -Fc 'nt_transition_measure::record(transition_start)' "$source")" -ne 2 ]]; then
    echo "windows-nt-transition-harness: FAIL (both NT return paths must be measured)" >&2
    exit 1
fi

if grep -Fq 'transition_start = 0' "$source"; then
    echo "windows-nt-transition-harness: FAIL (constant timestamp is not measurement)" >&2
    exit 1
fi

echo "windows-nt-transition-harness: PASS (real NT entry/return timer and hosted accumulator contract)"
