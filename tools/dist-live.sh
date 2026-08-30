#!/usr/bin/env bash
# Builds the downloadable live images and stages them for a web repo.
#
#   tools/dist-live.sh [profile ...]
#
# Each profile produces ONE bootable ISO -- an isohybrid, so the same file
# boots a CD, a USB stick written with dd, and a VM, on BIOS or UEFI. That is
# what a download has to be: nothing to assemble and nothing to pair with a
# separate kernel.
#
# Names and tree follow ../images/docs/media-naming.md, which is the contract:
# both formulas, where each field comes from, and the mirror they were checked
# against. Change that document and this script in the same pass.
#
# The image is what gets served. Compressing it is nearly pointless and was
# measured rather than assumed: the payload is an already-zstd-19 squashfs, so
# 7z finds only the sparse GRUB/GPT regions and the gzipped kernel -- 15% off
# nano, 4% off micro. The ISO is already one file, and it is directly
# dd-able to a USB stick, so a 4% saving does not earn a decompression step.
# ARCHIVE=1 stages a .7z alongside it for anyone who wants one.
#
# Env:
#   ARCHES     space-separated, default the host arch
#   DIST       output directory, default <images repo>/dist
#   VERSION    override the release number the image reports about itself
#   COMPOSE    override the compose id (default <UTC date>.<respin>)
#   ARCHIVE    1 to also stage a .7z beside each image (default 0)
set -euo pipefail
HERE="$(cd "$(dirname "$0")/.." && pwd)"
cd "$HERE"

PROFILES=("$@")
[ ${#PROFILES[@]} -gt 0 ] || PROFILES=(micro nano)
host_arch="$(uname -m)"
read -r -a ARCHES <<<"${ARCHES:-$host_arch}"
# The images belong to the images repo: it owns userspace composition, and the
# kernel repo is not where build output of somebody else lives.
DIST="${DIST:-${OXIDE_IMAGES_DIR:-$HERE/../images}/dist}"
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
# The release number is NOT kept here. oxide-release owns it -- it renders
# /usr/lib/os-release, and VERSION_ID is what the running system reports about
# itself -- so the image is asked what it is rather than a second copy of the
# number being maintained alongside it. Fedora works the same way, with
# fedora-release owning the number its media are named after.
#
# The compose id distinguishes two BUILDS of one release -- the job Fedora
# gives the trailing 1.6 in Fedora-Workstation-Live-x86_64-42-1.6.iso, and the
# .n.0 in a nightly's Fedora-42-20260830.n.0. A release number alone cannot
# say which build a file is, so rebuilding on one day would either overwrite
# yesterday's answer or silently ship two different files under one name.
# The respin is derived from what is already staged, so a rebuild is a new
# build number without anyone having to remember to bump one.
COMPOSE_DATE="${COMPOSE_DATE:-$(date -u +%Y%m%d)}"
command -v unsquashfs >/dev/null || die "need unsquashfs (squashfs-tools) to read the image version"

release_of() {  # <squashfs> -> VERSION_ID
  local v
  v="$(unsquashfs -cat "$1" usr/lib/os-release 2>/dev/null \
       | sed -n 's/^VERSION_ID=//p' | tr -d '"' | head -1)"
  [ -n "$v" ] || die "no VERSION_ID in $1 — is oxide-release installed in that profile?"
  printf '%s' "$v"
}

mkdir -p "$DIST"

# Highest respin already staged for today, plus one; 0 when today has none.
if [ -z "${COMPOSE:-}" ]; then
  respin=0
  # <date>.<respin> sits before the .<arch>.iso suffix, so strip two extensions.
  while IFS= read -r f; do
    n="${f%.iso}"; n="${n%.*}"; n="${n##*.}"
    case "$n" in ''|*[!0-9]*) continue ;; esac
    [ "$n" -ge "$respin" ] && respin=$((n + 1))
  done < <(find "$DIST" -name "Oxide-*-${COMPOSE_DATE}.*.iso" 2>/dev/null)
  COMPOSE="${COMPOSE_DATE}.${respin}"
fi
echo "dist-live: compose $COMPOSE"

staged=()

for arch in "${ARCHES[@]}"; do
  for profile in "${PROFILES[@]}"; do
    tag="$profile-$arch"
    # Fail on a missing root BEFORE spending a kernel build on it. The images
    # repo owns userspace; this script never composes one.
    sqfs="$IMAGES/out/${profile}-${arch}-root-slim.squashfs"
    [ -f "$sqfs" ] || sqfs="$IMAGES/out/${profile}-${arch}-root.squashfs"
    [ -f "$sqfs" ] || die "no packed root for $tag — run: (cd $IMAGES && make ${profile}-${arch})"
    # aarch64 boots as an EFI application, so GRUB's arm64-efi module set has
    # to be vendored. Checked here rather than after a two-minute kernel build
    # that would be thrown away.
    [ "$arch" != aarch64 ] || [ -d "$HERE/vendor/grub/arm64-efi" ] \
      || die "no vendored arm64-efi GRUB modules — run: ./tools/fetch-vendor.sh"

    # The same two steps `make live-x86` runs. Building without exporting
    # boots a STALE kernel from target/artifacts, which live-image.sh reads --
    # so the export is not optional and never separated from the build.
    echo "==> $tag: kernel"
    cargo run --quiet -p xtask -- kernel --arch "$arch"
    cargo run --quiet -p xtask -- artifacts --arch "$arch"

    echo "==> $tag: live image"
    img="$HERE/target/oxide-live-${tag}.iso"
    OXIDE_LIVE_IMG="$img" ./tools/live-image.sh "$profile" "$arch"
    [ -f "$img" ] || die "live-image.sh produced no $img"

    # ../images/docs/media-naming.md:
    #   <Product>-<Edition>-<Media>-<Release>-<Compose>.<Arch>.iso
    #   dist/releases/<Release>/<Edition>/<Arch>/iso/
    # Arch is LAST and dot-separated: Fedora moved it there, and a name that
    # matches what mirroring tools and visitors already parse is worth more
    # than one we invented.
    rel="${VERSION:-$(release_of "$sqfs")}"
    edition="$(printf '%s' "${profile:0:1}" | tr a-z A-Z)${profile:1}"
    leaf="$DIST/releases/$rel/$edition/$arch/iso"
    mkdir -p "$leaf"
    base="Oxide-${edition}-Live-${rel}-${COMPOSE}.${arch}"
    out="$leaf/${base}.iso"
    mv -f "$img" "$out"

    # Fedora puts the checksum beside the image, one per edition and arch,
    # so a visitor who downloaded one file can verify it without fetching an
    # index covering media they did not want.
    ( cd "$leaf" && sha256sum "${base}.iso" \
        > "Oxide-${edition}-${rel}-${COMPOSE}-${arch}-CHECKSUM" )

    staged+=("releases/$rel/$edition/$arch/iso/${base}.iso"
             "releases/$rel/$edition/$arch/iso/Oxide-${edition}-${rel}-${COMPOSE}-${arch}-CHECKSUM")
    printf '    %-52s %s\n' "${base}.iso" "$(du -h "$out" | cut -f1)"

    if [ "$ARCHIVE" = "1" ]; then
      echo "==> $tag: archive"
      rm -f "$out.7z"
      "$SEVENZ" a -bso0 -bsp0 -t7z -mx=9 "$out.7z" "$out" >/dev/null
      [ -f "$out.7z" ] || die "7-Zip produced no $out.7z"
      staged+=("releases/$rel/$edition/$arch/iso/${base}.iso.7z")
      printf '    %-52s %s\n' "${base}.iso.7z" "$(du -h "$out.7z" | cut -f1)"
    fi
  done
done

# The index a download page is generated from, at the ROOT of the tree because
# it indexes ACROSS releases -- a page should not have to walk a directory tree
# to find out what exists.
#
# Built by WALKING THE TREE, not from this run's output. A run that builds one
# arch, or one profile, would otherwise rewrite the index with only what it
# just made and silently un-publish everything else. The files on disk are the
# truth; this only reports them.
{
  printf '{\n  "compose": "%s",\n  "built": "%s",\n  "files": [\n' \
    "$COMPOSE" "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  sep=""
  while IFS= read -r iso; do
    name="$(basename "$iso")"
    relpath="${iso#$DIST/}"
    # releases/<release>/<Edition>/<arch>/iso/<file>
    IFS=/ read -r _ m_rel m_ed m_arch _ _ <<<"$relpath"
    # <Product>-<Edition>-Live-<release>-<compose>.<arch>.iso
    m_compose="${name%.*.iso}"; m_compose="${m_compose##*-}"
    sum="$(dirname "$iso")/Oxide-${m_ed}-${m_rel}-${m_compose}-${m_arch}-CHECKSUM"
    [ -f "$sum" ] || die "no CHECKSUM beside $relpath"
    printf '%s    {"path": "%s", "edition": "%s", "arch": "%s", "release": "%s", "compose": "%s", "bytes": %s, "sha256": "%s"}' \
      "$sep" "$relpath" "$m_ed" "$m_arch" "$m_rel" "$m_compose" \
      "$(stat -c %s "$iso")" "$(cut -d' ' -f1 < "$sum")"
    sep=$',\n'
  done < <(find "$DIST/releases" -name '*.iso' | sort)
  printf '\n  ]\n}\n'
} > "$DIST/manifest.json"
python3 -c "import json,sys; json.load(open(sys.argv[1]))" "$DIST/manifest.json" \
  || die "manifest.json is not valid JSON"
staged+=("manifest.json")
echo "dist-live: staged ${#staged[@]} file(s) in $DIST"
( cd "$DIST" && ls -l "${staged[@]}" )
