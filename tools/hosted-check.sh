#!/usr/bin/env bash
# hosted-check: type-check every workspace crate ON ITS OWN, for the host,
# with its own default features.
#
# Why per-crate and not `cargo check --workspace`: cargo unifies features
# across everything one invocation builds. `socket` depends on
# `net = { features = ["hosted"] }`, so a workspace-wide check turns `hosted`
# ON for `net`, and a crate that only compiles WITH that feature still passes.
# `cargo check -p net` resolves `net`'s own default features and does not.
#
# The defect class: an ungated module referencing a module gated behind
# `#[cfg(any(target_os = "oxide-kernel", test, feature = "hosted"))]`. Every
# other routine gate misses it — `cargo test` turns the gate on through
# `cfg(test)`, both kernel builds turn it on through `target_os`, and a
# workspace check turns it on through unification. It reaches main as a red
# `cargo check -p <crate>` for anyone building that crate alone (B1660).
#
# HOSTED_CHECK_JOBS caps the parallel invocations (default: half the CPUs, so a
# shared box keeps room for the other lanes' builds).
set -uo pipefail

cd "$(dirname "$0")/.."

jobs="${HOSTED_CHECK_JOBS:-$(( $(nproc 2>/dev/null || echo 4) / 2 ))}"
[ "$jobs" -lt 1 ] && jobs=1

crates="$(cargo metadata --no-deps --format-version 1 \
    | python3 -c 'import json,sys; print("\n".join(p["name"] for p in json.load(sys.stdin)["packages"]))')"

if [ -z "$crates" ]; then
    echo "hosted-check: cargo metadata produced no workspace members" >&2
    exit 1
fi

count="$(echo "$crates" | grep -c .)"
failed="$(echo "$crates" | xargs -P "$jobs" -I '{}' \
    sh -c 'cargo check --quiet -p "$1" >/dev/null 2>&1 || echo "$1"' _ '{}')"

if [ -n "$failed" ]; then
    echo "hosted-check: FAIL — these crates do not type-check on their own:" >&2
    for name in $failed; do
        echo "  --- cargo check -p $name ---" >&2
        cargo check --quiet -p "$name" 2>&1 | sed 's/^/  /' >&2
    done
    exit 1
fi

echo "hosted-check: PASS — $count crates type-check in isolation ($jobs jobs)"
