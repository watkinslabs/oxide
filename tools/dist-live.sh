#!/usr/bin/env bash
# Builds the downloadable live images and stages them for a web repo.
#
#   tools/dist-live.sh [profile ...]
#
# Each profile produces ONE bootable file (GRUB BIOS + UEFI, the stripped
# kernel, an immutable squashfs root with volatile writes), which is what a
# download has to be: nothing to assemble, nothing to pair with a separate
# kernel, writable to a USB stick byte for byte.
#
# The image is what gets served. Compressing it is nearly pointless and was
# measured rather than assumed: the payload is an already-zstd-19 squashfs, so
# 7z finds only the sparse GRUB/GPT regions and the gzipped kernel -- 15% off
# nano, 4% off micro. A raw .img is already one file, and it is directly
# dd-able to a USB stick, so a 4% saving does not earn a decompression step.
# ARCHIVE=1 stages a .7z alongside it for anyone who wants one.
#
# Env:
#   ARCHES     space-separated, default the host arch
#   DIST       output directory, default dist/
#   VERSION    stamped into the file names, default the git describe/date
#   ARCHIVE    1 to also stage a .7z beside each image (default 0)
set -euo pipefail
HERE="$(cd "$(dirname "$0")/.." && pwd)"
cd "$HERE"

PROFILES=("$@")
[ ${#PROFILES[@]} -gt 0 ] || PROFILES=(micro nano)
host_arch="$(uname -m)"
read -r -a ARCHES <<<"${ARCHES:-$host_arch}"
DIST="${DIST:-$HERE/dist}"
ARCHIVE="${ARCHIVE:-0}"
IMAGES="${OXIDE_IMAGES_DIR:-$HERE/../images}"

die() { echo "dist-live: $*" >&2; exit 1; }

# 7-Zip ships under three different command names depending on the package
# (7zip, p7zip, p7zip-plugins). Take whichever is installed rather than
# hard-coding one and failing on a box that has another.
SEVENZ=""
for c in 7zz 7za 7z; do command -v "$c" >/dev/null && { SEVENZ="$c"; break; }; done
[ "$ARCHIVE" != "1" ] || [ -n "$SEVENZ" ] || die "ARCHIVE=1 but no 7-Zip — install it: sudo dnf install -y 7zip"
command -v sha256sum >/dev/null || die "need sha256sum (coreutils)"

# A downloadable file has to say which build it is, and a date alone cannot
# distinguish two builds in one day. Prefer git's answer; fall back to a
# timestamp outside a checkout.
if [ -z "${VERSION:-}" ]; then
  VERSION="$(git -C "$HERE" describe --tags --always --dirty 2>/dev/null || true)"
  [ -n "$VERSION" ] || VERSION="$(date -u +%Y%m%d)"
fi

mkdir -p "$DIST"
staged=()

for arch in "${ARCHES[@]}"; do
  for profile in "${PROFILES[@]}"; do
    tag="$profile-$arch"
    # Fail on a missing root BEFORE spending a kernel build on it. The images
    # repo owns userspace; this script never composes one.
    sqfs="$IMAGES/out/${profile}-${arch}-root-slim.squashfs"
    [ -f "$sqfs" ] || sqfs="$IMAGES/out/${profile}-${arch}-root.squashfs"
    [ -f "$sqfs" ] || die "no packed root for $tag — run: (cd $IMAGES && make ${profile}-${arch})"

    # The same two steps `make live-x86` runs. Building without exporting
    # boots a STALE kernel from target/artifacts, which live-image.sh reads --
    # so the export is not optional and never separated from the build.
    echo "==> $tag: kernel"
    cargo run --quiet -p xtask -- kernel --arch "$arch"
    cargo run --quiet -p xtask -- artifacts --arch "$arch"

    echo "==> $tag: live image"
    img="$HERE/target/oxide-live-${tag}.img"
    OXIDE_LIVE_IMG="$img" ./tools/live-image.sh "$profile" "$arch"
    [ -f "$img" ] || die "live-image.sh produced no $img"

    out="$DIST/oxide-live-${tag}-${VERSION}.img"
    mv -f "$img" "$out"

    staged+=("$(basename "$out")")
    printf '    %-46s %s\n' "$(basename "$out")" "$(du -h "$out" | cut -f1)"

    if [ "$ARCHIVE" = "1" ]; then
      echo "==> $tag: archive"
      rm -f "$out.7z"
      "$SEVENZ" a -bso0 -bsp0 -t7z -mx=9 "$out.7z" "$out" >/dev/null
      [ -f "$out.7z" ] || die "7-Zip produced no $out.7z"
      staged+=("$(basename "$out.7z")")
      printf '    %-46s %s\n' "$(basename "$out.7z")" "$(du -h "$out.7z" | cut -f1)"
    fi
  done
done

# Checksums over exactly what is being published, regenerated whole so a
# stale line cannot survive a rebuild.
( cd "$DIST" && sha256sum "${staged[@]}" > SHA256SUMS )
echo "dist-live: staged ${#staged[@]} file(s) in $DIST"
( cd "$DIST" && ls -la "${staged[@]}" SHA256SUMS )
