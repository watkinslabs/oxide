#!/usr/bin/env bash
# lazygit 0.44.1 build recipe — static binaries checked in as
# vendor/lazygit/lazygit-{x86_64,aarch64}. lazygit is a Go program; the
# main package is the repo root (main.go, package main). Built with the
# vendored host Go SDK (vendor/go/bin/go): Go cross-compiles natively via
# GOOS/GOARCH, no cross-toolchain. CGO_ENABLED=0 yields fully-static
# binaries with no libc / dynamic-linker dependency (matches the
# static-musl userspace). GOPATH/GOCACHE live under /tmp so the build
# does not pollute the repo; Go fetches module deps from the network
# (expected). Installs to /usr/bin/lazygit.
set -e
cd "$(dirname "$0")"
SRC="lazygit-0.44.1"
[ -d "$SRC" ] || { echo "missing $SRC — run tools/fetch-lazygit.sh first" >&2; exit 1; }
ROOT="$(cd ../.. && pwd)"
GO="$ROOT/vendor/go/bin/go"
[ -x "$GO" ] || { echo "fetching Go SDK"; "$ROOT/tools/fetch-go.sh"; }
[ -x "$GO" ] || { echo "missing $GO — tools/fetch-go.sh failed" >&2; exit 1; }

export GOCACHE=/tmp/gocache
export GOPATH=/tmp/gopath
export GOFLAGS=-trimpath
export CGO_ENABLED=0
export GOOS=linux

( cd "$SRC" && GOARCH=amd64 "$GO" build -ldflags='-s -w' -o ../lazygit-x86_64 . )
( cd "$SRC" && GOARCH=arm64 "$GO" build -ldflags='-s -w' -o ../lazygit-aarch64 . )

echo "lazygit: $(ls -la lazygit-x86_64 lazygit-aarch64 | awk '{print $NF, $5}')"
