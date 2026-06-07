#!/usr/bin/env bash
# duf 0.8.1 build recipe — static binaries checked in as
# vendor/duf/duf-{x86_64,aarch64}. duf is a Go program (df alternative);
# the main package is the repo root (.). Built with the vendored host Go
# SDK (vendor/go/bin/go): Go cross-compiles natively via GOOS/GOARCH, no
# cross-toolchain. CGO_ENABLED=0 yields fully-static binaries with no
# libc / dynamic-linker dependency (matches the static-musl userspace).
# GOPATH/GOCACHE live under /tmp so the build does not pollute the repo;
# Go fetches module deps from the network (expected).
set -e
cd "$(dirname "$0")"
SRC="duf-0.8.1"
[ -d "$SRC" ] || { echo "missing $SRC — run tools/fetch-duf.sh first" >&2; exit 1; }
ROOT="$(cd ../.. && pwd)"
GO="$ROOT/vendor/go/bin/go"
[ -x "$GO" ] || { echo "missing $GO — run tools/fetch-go.sh first" >&2; exit 1; }

export GOCACHE=/tmp/gocache
export GOPATH=/tmp/gopath
export GOFLAGS=-trimpath
export CGO_ENABLED=0
export GOOS=linux

( cd "$SRC" && GOARCH=amd64 "$GO" build -ldflags='-s -w' -o ../duf-x86_64 . )
( cd "$SRC" && GOARCH=arm64 "$GO" build -ldflags='-s -w' -o ../duf-aarch64 . )

echo "duf: $(ls -la duf-x86_64 duf-aarch64 | awk '{print $NF, $5}')"
