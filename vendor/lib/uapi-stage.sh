# Shared Linux-UAPI header staging for vendor cross-builds. Source this and
# call `uapi_cflags <arch>` to get the include flags a musl build needs.
#
#   x86_64 (host musl-gcc): musl-gcc's sysroot lacks the Linux UAPI headers
#     (linux/, asm/, asm-generic/, mtd/, scsi/, sound/, rdma/, xen/, misc/),
#     so stage host copies and -isystem them. Staged FRESH every call:
#     the old `test -d || cp` skip-if-exists left stale/empty /tmp dirs from
#     interrupted runs in place (asm/types.h never copied → build died).
#     `cp -rL` dereferences any symlinked uapi dirs.
#
#   aarch64 (cross): the aarch64-linux-musl-cross sysroot already carries the
#     full, arch-correct UAPI — use it. Emit NO -isystem: pulling in the host's
#     x86 headers is wrong-arch and the asm->asm-generic symlink hack dropped
#     asm/types.h.
#
# Usage:
#   . "$(dirname "$0")/../lib/uapi-stage.sh"
#   CFLAGS="-Os -static ... $(uapi_cflags x86_64)"   # or aarch64
uapi_cflags() {
  case "$1" in
    x86_64|x86)
      _H=/tmp/musl-uapi-x86
      rm -rf "$_H"; mkdir -p "$_H"
      for _d in linux asm asm-generic mtd scsi sound rdma xen misc; do
        cp -rL "/usr/include/$_d" "$_H/$_d" 2>/dev/null || true
      done
      printf -- '-isystem %s' "$_H"
      ;;
    aarch64|arm)
      : # cross sysroot already has the full UAPI; nothing to add
      ;;
    *)
      echo "uapi_cflags: unknown arch '$1'" >&2; return 2 ;;
  esac
}
