#!/usr/bin/env bash
# fzf 0.55.0 build recipe — static binaries checked in as
# vendor/fzf/fzf-{x86_64,aarch64}. fzf is a Go program; the main
# package is the repo root (.). Built with the vendored host Go SDK
# (vendor/go/bin/go): Go cross-compiles natively via GOOS/GOARCH, no
# cross-toolchain. CGO_ENABLED=0 yields fully-static binaries with no
# libc / dynamic-linker dependency (matches the static-musl userspace).
# GOPATH/GOCACHE live under /tmp so the build does not pollute the repo;
# Go fetches module deps from the network (expected).
set -e
cd "$(dirname "$0")"
SRC="fzf-0.55.0"
[ -d "$SRC" ] || { echo "missing $SRC — run tools/fetch-fzf.sh first" >&2; exit 1; }
ROOT="$(cd ../.. && pwd)"
GO="$ROOT/vendor/go/bin/go"
[ -x "$GO" ] || { echo "missing $GO — run tools/fetch-go.sh first" >&2; exit 1; }

export GOCACHE=/tmp/gocache
export GOPATH=/tmp/gopath
export GOFLAGS=-trimpath
export CGO_ENABLED=0
export GOOS=linux

( cd "$SRC" && GOARCH=amd64 "$GO" build -ldflags='-s -w' -o ../fzf-x86_64 . )
( cd "$SRC" && GOARCH=arm64 "$GO" build -ldflags='-s -w' -o ../fzf-aarch64 . )

echo "fzf: $(ls -la fzf-x86_64 fzf-aarch64 | awk '{print $NF, $5}')"
