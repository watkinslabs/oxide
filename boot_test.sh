#!/bin/bash
# Boot oxide x86_64 under qemu with unix-socket serial.
set +e
pkill -9 -f qemu-system
sleep 1
rm -f /tmp/v.sock /tmp/qemu.log
cd /home/nd/oxide2
nohup qemu-system-x86_64 -machine q35 -cpu host -enable-kvm -smp 2 -m 2G \
  -cdrom target/oxide-x86_64-grub.iso -boot d \
  -drive if=none,id=root,format=raw,file=$PWD/kernel/blobs/root-x86_64.img \
  -device virtio-blk-pci,drive=root,serial=oxide-root \
  -drive if=none,id=home,format=raw,file=$PWD/kernel/blobs/home-x86_64.img \
  -device virtio-blk-pci,drive=home,serial=oxide-home \
  -netdev user,id=net0 -device virtio-net-pci,netdev=net0 \
  -display none -no-reboot -serial unix:/tmp/v.sock,server,nowait > /tmp/qemu.log 2>&1 &
echo "qemu launched pid $!"
sleep 3
ls -la /tmp/v.sock 2>&1
echo "qemu pids: $(pgrep -f qemu-system)"
