#!/usr/bin/env bash
# micro 2.0.14 build recipe — static binaries checked in as
# vendor/micro/micro-{x86_64,aarch64}. micro is a Go program; the main
# package is ./cmd/micro. Built with the vendored host Go SDK
# (vendor/go/bin/go): Go cross-compiles natively via GOOS/GOARCH, no
# cross-toolchain. CGO_ENABLED=0 yields fully-static binaries with no
# libc / dynamic-linker dependency (matches the static-musl userspace).
# GOPATH/GOCACHE live under /tmp so the build does not pollute the repo;
# Go fetches module deps from the network (expected).
# micro's Makefile injects version via -X ldflags; a plain build is fine
# and reports version "unknown" — acceptable.
set -e
cd "$(dirname "$0")"
SRC="micro-2.0.14"
[ -d "$SRC" ] || { echo "missing $SRC — run tools/fetch-micro.sh first" >&2; exit 1; }
ROOT="$(cd ../.. && pwd)"
GO="$ROOT/vendor/go/bin/go"
[ -x "$GO" ] || { echo "missing $GO — run tools/fetch-go.sh first" >&2; exit 1; }

export GOCACHE=/tmp/gocache
export GOPATH=/tmp/gopath
export GOFLAGS=-trimpath
export CGO_ENABLED=0
export GOOS=linux

( cd "$SRC" && GOARCH=amd64 "$GO" build -ldflags='-s -w' -o ../micro-x86_64 ./cmd/micro )
( cd "$SRC" && GOARCH=arm64 "$GO" build -ldflags='-s -w' -o ../micro-aarch64 ./cmd/micro )

echo "micro: $(ls -la micro-x86_64 micro-aarch64 | awk '{print $NF, $5}')"
