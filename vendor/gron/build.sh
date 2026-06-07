#!/usr/bin/env bash
# gron 0.7.1 build recipe — static binaries checked in as
# vendor/gron/gron-{x86_64,aarch64}. gron is a Go program; the main
# package is the repo root (.). Built with the vendored host Go SDK
# (vendor/go/bin/go): Go cross-compiles natively via GOOS/GOARCH, no
# cross-toolchain. CGO_ENABLED=0 yields fully-static binaries with no
# libc / dynamic-linker dependency (matches the static-musl userspace).
# GOPATH/GOCACHE live under /tmp so the build does not pollute the repo;
# Go fetches module deps from the network (expected).
set -e
cd "$(dirname "$0")"
SRC="gron-0.7.1"
[ -d "$SRC" ] || { echo "missing $SRC — run tools/fetch-gron.sh first" >&2; exit 1; }
ROOT="$(cd ../.. && pwd)"
GO="$ROOT/vendor/go/bin/go"
[ -x "$GO" ] || { echo "vendor/go/bin/go missing — running tools/fetch-go.sh" >&2; "$ROOT/tools/fetch-go.sh"; }

export GOCACHE=/tmp/gocache
export GOPATH=/tmp/gopath
export GOFLAGS=-trimpath
export CGO_ENABLED=0
export GOOS=linux

( cd "$SRC" && GOARCH=amd64 "$GO" build -ldflags='-s -w' -o ../gron-x86_64 . )
( cd "$SRC" && GOARCH=arm64 "$GO" build -ldflags='-s -w' -o ../gron-aarch64 . )

echo "gron: $(ls -la gron-x86_64 gron-aarch64 | awk '{print $NF, $5}')"
