#!/usr/bin/env bash
# test-build-check: BUILD every workspace crate's test targets ON ITS OWN,
# with that crate's own default features.
#
# The gap this closes, measured not theorised: `cargo test -p procfs` did not
# build at all on main. Its 155 tests only ever ran under
# `cargo test --workspace`, where another member's dev-dependency turned on
# `sched/hosted` through cargo's feature unification. `hosted-gate` did not
# catch it because `cargo check -p <crate>` COMPILES NO TEST TARGETS — the
# `#[cfg(test)]` tree, the `tests/` directory and every dev-dependency are
# outside what `cargo check` builds. So a crate whose tests do not compile in
# isolation passes `hosted-gate`, `make test`, both kernel builds and CI, and
# the only signal is a lane that happens to run `cargo test -p <that crate>`.
#
# `--no-run` and not a run: the defect class is a BUILD failure, and building
# the test binaries is the whole cost. Running them is `make test`'s job.
#
# TEST_BUILD_CHECK_JOBS caps parallel invocations (default: half the CPUs).
# Cargo holds an exclusive lock on the target directory while it builds, so the
# jobs overlap on resolution and queue on codegen; the cap is about leaving a
# shared box room for other lanes, not about throughput.
set -uo pipefail

cd "$(dirname "$0")/.."

jobs="${TEST_BUILD_CHECK_JOBS:-$(( $(nproc 2>/dev/null || echo 4) / 2 ))}"
[ "$jobs" -lt 1 ] && jobs=1

crates="$(cargo metadata --no-deps --format-version 1 \
    | python3 -c 'import json,sys; print("\n".join(p["name"] for p in json.load(sys.stdin)["packages"]))')"

if [ -z "$crates" ]; then
    echo "test-build-check: cargo metadata produced no workspace members" >&2
    exit 1
fi

count="$(echo "$crates" | grep -c .)"
failed="$(echo "$crates" | xargs -P "$jobs" -I '{}' \
    sh -c 'cargo test --no-run --quiet -p "$1" >/dev/null 2>&1 || echo "$1"' _ '{}')"

if [ -n "$failed" ]; then
    echo "test-build-check: FAIL — these crates' test targets do not build on their own:" >&2
    for name in $failed; do
        echo "  --- cargo test --no-run -p $name ---" >&2
        cargo test --no-run --quiet -p "$name" 2>&1 | sed 's/^/  /' >&2
    done
    exit 1
fi

echo "test-build-check: PASS — $count crates build their test targets in isolation ($jobs jobs)"
