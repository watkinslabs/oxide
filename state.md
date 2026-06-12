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
- **F454 #1833** PR-B: `crates/drivers/drv-virtio-snd` crate — CONTROLQ engine
  (`submit_ctl` 2-desc chain req-RO/resp-WO, poll used ring) + `R_PCM_INFO`
  query + `virtio_snd_config` harvest (`virtio_snd_cfg.rs`). Boot line verified
  BOTH arches: `virtio-snd: bdf=0:8.0 card=C0 streams=2 out=1 in=1`. QEMU
  `virtio-sound-pci,audiodev=none,disable-legacy=on` added to both arch boots.
  `config()` accessor exposes jacks/streams/chmaps/controls.
- **F455 (this branch)** PR-C: PCM playback. TXQ(2) programmed via `program_queue`
  + `notify_va` helper (VirtioProbe `snd_q2_*`). `beep(hz,ms)`/`beep_diag`:
  SET_PARAMS(S16 mono 44.1k)→PREPARE→START→3-desc TX chains (xfer/payload/status)
  →STOP. Verified BOTH arches `boot-tone diag=0`; x86 wav backend captured the
  exact ±8000 square wave (peak_abs=8000, non-zero PCM). **LOCKSTEP GOTCHA fixed:**
  virtio-sound retires TX via the audio-backend timer (not synchronously like
  CONTROLQ); under ARM TCG a tight busy-poll holds the QEMU BQL and starves that
  timer → diag=7 timeout. Fix: `tx_period` poll reads device_status (cfg_va+0x14)
  each iteration to force a VM exit, releasing the BQL (Ctx now carries cfg_va).

### NEXT TASK — PR-D: ALSA `/dev/snd/*` nodes (then PR-E OSS `/dev/dsp`)
`crates/kernel/sound` glue: controlC0 (minor card*32+0) + pcmC0D0p (card*32+16),
`SNDRV_PCM_IOCTL_*` (docs/58§5.1) → drv-virtio-snd. HW_PARAMS→SET_PARAMS,
PREPARE/START/DROP, WRITEI_FRAMES→a `pcm_write` (generalise `beep`'s TX loop into
a public `pcm_write(stream,bytes)`). `drv_virtio_snd::config()` sizes the card;
`output_stream()` gives the default playback stream. Also wire `beep` into the
`50§16` KIOCSOUND/KDMKTONE VT backend. Then PR-E OSS `/dev/dsp` (major 14).
2. Mouse/pointer: virtio-tablet/mouse 2nd evdev node (event1, EV_REL/EV_ABS/BTN_*).
3. Ethernet: e1000/rtl8139 PCI drivers (oxide DHCP is a static seed — see memory).
4. 3D/virgl + Xorg/Mesa userspace. 5. Module lifecycle (modules/lib.rs).

## First command next session
    sed -n '131,168p' docs/58-virtio-snd.md   # §5 ALSA /dev/snd nodes + PCM ioctls
