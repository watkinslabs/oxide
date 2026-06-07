#!/usr/bin/env bash
# yq 4.44.3 build recipe — static binaries checked in as
# vendor/yq/yq-{x86_64,aarch64}. yq (github.com/mikefarah/yq) is a Go
# program; the main package is the repo root (.). Built with the
# vendored host Go SDK (vendor/go/bin/go): Go cross-compiles natively
# via GOOS/GOARCH, no cross-toolchain. CGO_ENABLED=0 yields fully-static
# binaries with no libc / dynamic-linker dependency (matches the
# static-musl userspace). GOPATH/GOCACHE live under /tmp so the build
# does not pollute the repo; Go fetches module deps from the network.
set -e
cd "$(dirname "$0")"
SRC="yq-4.44.3"
[ -d "$SRC" ] || { echo "missing $SRC — run tools/fetch-yq.sh first" >&2; exit 1; }
ROOT="$(cd ../.. && pwd)"
GO="$ROOT/vendor/go/bin/go"
[ -x "$GO" ] || { echo "missing $GO — fetching Go SDK"; "$ROOT/tools/fetch-go.sh"; }

export GOCACHE=/tmp/gocache
export GOPATH=/tmp/gopath
export GOFLAGS=-trimpath
export CGO_ENABLED=0
export GOOS=linux

( cd "$SRC" && GOARCH=amd64 "$GO" build -ldflags='-s -w' -o ../yq-x86_64 . )
( cd "$SRC" && GOARCH=arm64 "$GO" build -ldflags='-s -w' -o ../yq-aarch64 . )

echo "yq: $(ls -la yq-x86_64 yq-aarch64 | awk '{print $NF, $5}')"
