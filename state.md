# state — session hand-off

Branch: **main**. Counters in `metadata/index.md` (AUTHORITATIVE — read+bump per
branch). Dev loop: `tools/boot-smoke-probe.sh x86 <probe>` under `OXIDE_QEMU_KVM=1`
(~20s); `tools/boot-smoke-login.sh x86` for the full login gate. **GOTCHA:** never
`pkill -f qemu-system` (kills the shell) AND `pkill -x` can't match the >15-char
process names — find PIDs via `pgrep -af qemu-system` and `kill -9 <pid>`. A stale
qemu holds the vsock guest-cid=3 AND the root.img write-lock; kill ALL qemu (both
arches) before any boot, or `vhost-vsock: cid Address already in use` fails the arm boot.

## Active run — AUDIO (virtio-snd) then mouse/USB-HID, eth, 3D, modules (gap list)

User directive: work the gap list to **100% Linux compat**, the Linux way — NO
hacks/stubs/façades. Both arches lockstep. Assembly stays in
`crates/arch/hal-{x86_64,aarch64}`. Self-paced `/loop` — do not stop at phase seams.

### Done this run
- **F453 #1831** `docs/58` FROZEN — virtio-snd wire protocol + ALSA/OSS UAPI.
- **C89 #1832** PR-A: extracted `pci-boot/src/virtio_qsetup.rs::program_queue` —
  uniform per-queue setup (alloc+zero rings, program desc/driver/device PAs, bind
  msix, enable, capture notify_off). virtio_drv.rs 908→826 lines. Both arches boot.
- **F454 (this branch)** PR-B: `crates/drivers/drv-virtio-snd` crate — CONTROLQ
  engine (`submit_ctl` 2-desc chain req-RO/resp-WO, poll used ring) + `R_PCM_INFO`
  query + `virtio_snd_config` harvest (`virtio_snd_cfg.rs`). Boot line verified
  BOTH arches: `virtio-snd: bdf=0:8.0 card=C0 streams=2 out=1 in=1`. QEMU
  `virtio-sound-pci,audiodev=none,disable-legacy=on` added to both arch boots
  (image_qemu.rs). `config()` accessor exposes jacks/streams/chmaps/controls.

### NEXT TASK — PR-C: PCM playback + tone (virtio-snd)

Program TXQ(2)/RXQ(3) for snd via `program_queue` (extend VirtioProbe with
q2_*/q3_* PAs+notify_va, OR program inside the snd install). Then on TXQ:
`SET_PARAMS`(0x0101)/`PREPARE`(0x0102)/`START`(0x0104) control reqs (reuse
`submit_ctl` — already generic over req/resp len), then push a period-buffer
3-desc chain (`virtio_snd_pcm_xfer` hdr RO + PCM payload RO + `virtio_snd_pcm_status`
WO) onto TXQ, advance avail, notify; used ring retires → free period + bump hw_ptr.
`beep(hz,ms)` synth square wave. VERIFY: swap the boot `audiodev none` for
`-audiodev wav,id=snd0,path=/tmp/out.wav` and assert out.wav has non-zero PCM.
Wire `beep` into `50§16` KIOCSOUND backend.

Wire types already in `drv-virtio-snd/src/lib.rs`: status codes, R_PCM_*, D_OUTPUT/
INPUT. `virtio_snd_pcm_set_params` layout = hdr(8: code+stream_id) + buffer_bytes(4)
+ period_bytes(4) + features(4) + channels(1) format(1) rate(1) pad(1) (docs/58§4).

## After PR-C (gap list order)
- PR-D ALSA `/dev/snd/*` (controlC0 + pcmC0D0p, SNDRV_PCM_IOCTL_*) + PR-E OSS `/dev/dsp`.
  `drv_virtio_snd::config()` sizes the card. controls=0 unless VIRTIO_SND_F_CTLS.
2. Mouse/pointer: virtio-tablet/mouse 2nd evdev node (event1, EV_REL/EV_ABS/BTN_*).
3. Ethernet: e1000/rtl8139 PCI drivers (oxide DHCP is a static seed — see memory).
4. 3D/virgl + Xorg/Mesa userspace. 5. Module lifecycle (modules/lib.rs).

## First command next session
    sed -n '1,30p' docs/58-virtio-snd.md   # §6 device-operation (TXQ playback)
