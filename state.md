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

- **F456 (this branch)** PR-D: ALSA sound subsystem, the Linux way (user
  insisted: no shortcuts, ALSA primary + OSS emulation on the SAME engine).
  - drv-virtio-snd refactored to real `snd_pcm_ops`: `pcm_hw_params` (release-
    if-needed then SET_PARAMS) / `pcm_prepare` / `pcm_trigger` / `pcm_hw_free` /
    `pcm_submit` + `pcm_caps` (per-stream formats/rates/ch from PCM_INFO) +
    `PcmState`. `beep` rebuilt on the private primitives (self-test unchanged).
  - NEW `crates/kernel/sound` = ALSA PCM core: substream state machine +
    `hw_params` refinement against device caps (uapi.rs has exact LP64 offsets
    from the cross-toolchain asound.h) + sw_params + appl/hw_ptr accounting +
    full `SNDRV_PCM_IOCTL_*`/`SNDRV_CTL_IOCTL_*` ABI. Nodes: `/dev/snd/controlC0`
    + `/dev/snd/pcmC0D0p` (primary), `/dev/dsp`/`/dev/audio`/`/dev/mixer`
    (snd-pcm-oss emulation, oss.rs). `sound::handle_ioctl` in the 016_ioctl
    chain; `sound::init()` in kmain after PCI enum.
  - Smoke: `userspace/snd_probe/snd_probe.c` (self-contained UAPI) drives the
    real libasound sequence + asserts HW_PARAMS REJECTS FLOAT64 + pins
    S16/2/44.1k + OSS path. PASS both arches. In oxide-smokes.sh + CRT_BINS.
  - **GOTCHA fixed:** sw_params `boundary` is @64 not @56 (silence_size@56).

- **F457 (this branch)** PR-E: capture (RXQ), full-duplex. Boot probe programs
  RXQ(3) like TXQ(2). drv-virtio-snd capture ops mirror playback:
  `cap_caps`/`cap_hw_params`/`cap_prepare`/`cap_trigger`/`cap_hw_free`/`pcm_recv`
  + `rx_period` (3-desc chain, payload WO; reads used-len for captured bytes;
  same BQL-yield). sound crate: `capture.rs` substream + `/dev/snd/pcmC0D0c`
  (READI/read) sharing `pcm::refine_params` (refactored pure/direction-agnostic);
  OSS `/dev/dsp` read(2). snd_probe extended (capture HW_PARAMS/PREPARE/READI),
  PASS both arches. QEMU null-audiodev capture yields silence frames.

### NEXT TASK — MOUSE (user: "then the mouse when done with all things audio")
Audio is functionally done (playback+capture+ALSA+OSS; mixer needs F_CTLS which
QEMU doesn't offer; KIOCSOUND console beep needs async kthread infra — deferred).
- Mouse: QEMU `-device virtio-tablet-pci` (or virtio-mouse). 2nd evdev node
  `/dev/input/event1`. drv-virtio-input already drains all EV_* types (drain.rs
  push_event0) — needs a SECOND device instance + event1 node + EV_ABS/EV_REL/
  BTN_* reporting. Verify via QMP `input-send-event` (mouse move/click) → read
  event1 input_event records. Add to qemu args (image_qemu.rs) both arches.
2. Mouse/pointer: virtio-tablet/mouse 2nd evdev node (event1, EV_REL/EV_ABS/BTN_*).
3. Ethernet: e1000/rtl8139 PCI drivers (oxide DHCP is a static seed — see memory).
4. 3D/virgl + Xorg/Mesa userspace. 5. Module lifecycle (modules/lib.rs).

## First command next session
    grep -rn 'event0\|EvdevInode\|install_default' crates/drivers/drv-virtio-input/src/   # 2nd evdev node for mouse
