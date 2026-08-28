#!/usr/bin/env bash
# Builds ONE bootable image: GRUB, the kernel, and an immutable squashfs root
# in a single file that boots under QEMU and writes to a USB stick unchanged.
#
#   tools/live-image.sh [profile] [arch]
#
# GRUB's rescue image is the boot half — it already carries a BIOS chain and a
# UEFI one in a layout both firmwares accept, so the same file boots a machine
# with a CSM and one without. The root filesystem is APPENDED to it as a GPT
# partition, which is how a live image has always attached one.
#
# The root is immutable, so the boot line asks for a volatile upper layer:
# every write lands in memory and is discarded at power-off. That is what
# makes one file enough — there is no writable partition to carry state, and
# nothing to restore between boots.
#
# The kernel is STRIPPED into the image. Debug information is most of an
# unstripped build and none of it is read at run time.
set -euo pipefail
HERE="$(cd "$(dirname "$0")/.." && pwd)"

profile="${1:-micro}"; arch="${2:-x86_64}"
die() { echo "live-image.sh: $*" >&2; exit 1; }
for t in grub2-mkrescue xorriso sgdisk strip; do command -v "$t" >/dev/null || die "need $t"; done

images="${OXIDE_IMAGES_DIR:-$HERE/../images}"
# The slim pack when the images repo made one — it is the same system without
# the software OpenGL stack, which is more than half the bytes. OXIDE_LIVE_FULL
# takes the full pack instead.
sqfs="$images/out/${profile}-${arch}-root-slim.squashfs"
if [ -n "${OXIDE_LIVE_FULL:-}" ] || [ ! -f "$sqfs" ]; then
  sqfs="$images/out/${profile}-${arch}-root.squashfs"
fi
[ -f "$sqfs" ] || die "no squashfs at $sqfs — run: (cd $images && ./pack-squashfs.sh $profile $arch slim)"

# Each arch hands GRUB a different thing and GRUB boots it a different way:
# x86 takes the ELF through multiboot2, aarch64 takes a PE Image GRUB runs as
# an EFI application. The rescue image's modules differ with it — the host
# ships the x86 sets, and the arm64-efi set is vendored.
case "$arch" in
  x86_64)
    kernel="${OXIDE_KERNEL_ELF:-$HERE/target/artifacts/$arch/kernel.elf}"
    boot_name="oxide-${arch}"; boot_cmd="multiboot2"
    grub_dir=""
    ;;
  aarch64)
    kernel="${OXIDE_KERNEL_ELF:-$HERE/target/artifacts/$arch/kernel.Image}"
    boot_name="oxide-${arch}.Image"; boot_cmd="linux"
    grub_dir="$HERE/vendor/grub/arm64-efi"
    [ -d "$grub_dir" ] || die "no vendored arm64-efi modules — run tools/fetch-vendor.sh"
    ;;
  *) die "arch must be x86_64 or aarch64" ;;
esac
[ -f "$kernel" ] || die "no kernel at $kernel — run: make kernel artifacts ARCH=$arch"

out="${OXIDE_LIVE_IMG:-$HERE/target/oxide-live-${profile}-${arch}.img}"
work="$(mktemp -d)"; trap 'rm -rf "$work"' EXIT

# The root is named, not numbered: the rescue image lays down partitions of
# its own, so the appended one's INDEX is grub2-mkrescue's business, and a
# label resolves the same whether the recipient boots the file as a disk or
# as a CD.
ROOT_LABEL="oxide-root"
# The partition the append lands on. Verified against the built image below
# rather than trusted — a layout change must fail the build, not the boot.
ROOT_PART=4

mkdir -p "$work/stage/boot/grub"
# An ELF carries its debug sections into the image; the aarch64 Image is a
# flat PE that never had any.
if [ "$arch" = x86_64 ]; then
  strip -o "$work/stage/boot/$boot_name" "$kernel"
  stripped="$(du -h "$work/stage/boot/$boot_name" | cut -f1)"
  # Linux does not ship a raw kernel either: a bzImage is a compressed vmlinux
  # with a decompressor in front. GRUB does the same job here — it opens a
  # multiboot2 kernel through its file layer, which applies the gzip filter
  # transparently, so the image on disk is compressed and the image GRUB hands
  # multiboot2 is not. Nearly all of the file is `.text`, which is why this is
  # worth more than half the kernel's bytes.
  #
  # OXIDE_LIVE_RAW_KERNEL=1 declines, for bisecting a boot failure against an
  # uncompressed image.
  if [ -z "${OXIDE_LIVE_RAW_KERNEL:-}" ] && command -v gzip >/dev/null; then
    gzip -9 -c "$work/stage/boot/$boot_name" > "$work/stage/boot/$boot_name.gz"
    mv "$work/stage/boot/$boot_name.gz" "$work/stage/boot/$boot_name"
    echo "==> kernel $(du -h "$kernel" | cut -f1) → stripped $stripped → gzip $(du -h "$work/stage/boot/$boot_name" | cut -f1)"
  else
    echo "==> kernel $(du -h "$kernel" | cut -f1) → stripped $stripped"
  fi
else
  cp "$kernel" "$work/stage/boot/$boot_name"
  echo "==> kernel $(du -h "$kernel" | cut -f1)"
fi
# The same parameters every boot in this repository carries, plus the three
# this image needs: a squashfs root named by label, and the volatile layer that
# makes it writable. `rw` is not a contradiction with an immutable image — the
# overlay above it is what a remount touches.
cmdline="BOOT_IMAGE=/boot/${boot_name} root=PARTLABEL=${ROOT_LABEL}"
cmdline="$cmdline rootfstype=squashfs rootovl=tmpfs rw"
cmdline="$cmdline earlycon printk.time=1"
cmdline="$cmdline systemd.log_target=kmsg systemd.journald.forward_to_kmsg=1"
cmdline="$cmdline sysctl.kernel.sysrq=1 sysrq_always_enabled enforcing=0"
cmdline="$cmdline systemd.mask=firewalld.service systemd.mask=chronyd.service"
cmdline="$cmdline systemd.mask=ModemManager.service systemd.mask=plymouth-start.service"
cmdline="$cmdline systemd.mask=NetworkManager-wait-online.service"
cmdline="$cmdline systemd.mask=flatpak-add-fedora-repos.service"
cmdline="$cmdline systemd.debug_shell=tty9 oxide.bootargs=grub"
# Extra parameters for one build, without editing this file: a debug boot is
# `OXIDE_LIVE_CMDLINE_EXTRA="systemd.log_level=debug ..." tools/live-image.sh`.
[ -n "${OXIDE_LIVE_CMDLINE_EXTRA:-}" ] && cmdline="$cmdline ${OXIDE_LIVE_CMDLINE_EXTRA}"
# GRUB's own console: x86 drives the 16550 itself, while on aarch64 the
# firmware owns the port and routes it to the PL011.
# The LAST console token is the one `/dev/console` is, so the screen owns it
# and the serial port mirrors the kernel's own log. OXIDE_LIVE_SERIAL_CONSOLE
# swaps them, which is what makes a headless run's userspace output greppable.
if [ -n "${OXIDE_LIVE_SERIAL_CONSOLE:-}" ]; then vt_last="console=ttyS0,115200"; first="console=tty0"
else first="console=ttyS0,115200"; vt_last="console=tty0"; fi
if [ "$arch" = x86_64 ]; then
  cmdline="$cmdline $first $vt_last"
  term=$'insmod all_video\nset gfxmode=auto\nset gfxpayload=keep\nserial --unit=0 --speed=115200\nterminal_input serial console\nterminal_output serial gfxterm'
else
  if [ -n "${OXIDE_LIVE_SERIAL_CONSOLE:-}" ]; then first="console=tty0"; vt_last="console=ttyAMA0,115200"
  else first="console=ttyAMA0,115200"; vt_last="console=tty0"; fi
  cmdline="$cmdline $first $vt_last"
  term=$'terminal_input console\nterminal_output console'
fi
{
  printf 'set timeout=0\nset default=0\n%s\n\n' "$term"
  printf 'menuentry "oxide (live)" {\n    %s /boot/%s %s\n    boot\n}\n' \
    "$boot_cmd" "$boot_name" "$cmdline"
} > "$work/stage/boot/grub/grub.cfg"

# Only the modules this configuration reaches. The default copies every module
# GRUB has for every platform it can build, which is more bytes than the kernel.
MODULES="part_gpt part_msdos fat iso9660 ${boot_cmd} normal configfile echo gzio
         serial terminal gfxterm all_video search search_fs_uuid"
rm -f "$out.new"
grub2-mkrescue ${grub_dir:+-d "$grub_dir"} \
  --install-modules="$MODULES" --modules="$MODULES" \
  --fonts= --themes= --locales= -o "$out.new" "$work/stage" -- \
  -hfsplus off -append_partition "$((ROOT_PART - 1))" 0x83 "$sqfs" >/dev/null 2>&1

# Name the appended partition so the boot line's PARTLABEL resolves. Only the
# GPT entry's name field changes; the hybrid boot sector is untouched, which
# the check below re-reads to prove.
mbr_before="$(dd if="$out.new" bs=512 count=1 status=none | md5sum)"
sgdisk -c "${ROOT_PART}:${ROOT_LABEL}" "$out.new" >/dev/null 2>&1 || true
mbr_after="$(dd if="$out.new" bs=512 count=1 status=none | md5sum)"
[ "$mbr_before" = "$mbr_after" ] || die "naming the root partition rewrote the boot sector"
sgdisk -i "$ROOT_PART" "$out.new" | grep -q "name: '${ROOT_LABEL}'" \
  || die "partition $ROOT_PART is not the appended root — grub2-mkrescue's layout moved"

mv -f "$out.new" "$out"
echo "==> done: $out ($(du -h "$out" | cut -f1))"
echo "    boot it:  qemu-system-x86_64 -m 2048 -drive file=$out,format=raw,if=virtio"
