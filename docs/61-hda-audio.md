# 61 HD-Audio (Intel HDA controller + codec)

FROZEN 2026-08-15. Dep:`01`,`02`,`07`,`15`,`16`,`19`,`22`,`34`,`35`,`52`,`58`. Provides:`drv-hda`, the second ALSA card, the physical-machine audio path.

Full Linux compat surface: the HD-Audio controller register file, CORB/RIRB command transport, codec widget enumeration, the generic parser, stream DMA, and the ALSA PCM/control ABI as `58§4` defines it. No deferrals.

## 1 Purpose

`58` gives a virtual machine audio through virtio-snd. A physical machine has no virtio sound device; every x86 laptop and desktop since 2004, and every aarch64 board with a PCI HD-Audio block, presents an Intel HD-Audio controller instead. `drv-hda` is that path. It binds by PCI class, not by a vendor/device list, so an unknown machine works.

## 2 Invariants (frozen)

1. Driver lives in `crates/drivers/drv-hda`, per `52`. It matches PCI class `0x040300` on the `pci` bus and binds through the `drv::Driver` probe/remove path. Pure MMIO (BAR0) + HHDM (rings, BDLs, stream buffers); no arch-specific assembly — identical on x86_64 and aarch64.
2. Every decision that can be made without hardware is in an ungated module and is hosted-tested: command encoding, response decode, widget/pin/amplifier capability decode, pin default configuration, connection-list slots and range markers, the widget-graph walk, pin classification, route search, converter assignment, control naming, stream-format encoding, BDL construction, ring arithmetic. The gated modules are MMIO, DMA and registration only (`53` shape).
3. Command transport is CORB out / RIRB in. The write pointer never advances onto an unread entry. A response the ring does not deliver inside the response deadline falls back to the immediate-command registers, so a codec stays reachable on a controller whose response DMA is broken.
4. RIRB response interrupts are enabled only when the function obtained an interrupt vector. Without one the driver polls: `exec` drains the RIRB itself and the stream position comes from the link position register. Polled operation is a working transport, not a degraded one.
5. One HD-Audio function = one ALSA card, allocated the next free card index by `sound::reserve_card`. One PCM device (device 0) with one playback and one capture substream.
6. Codec enumeration walks root → audio function group → widgets exactly once at probe. The first slot in `STATESTS` that answers with an audio function group and yields a usable route is the card's codec.
7. The generic parser is the only routing policy. There is no vendor patch table: a codec is described entirely by its widget graph and its pin default configurations, and the parser's badness scoring picks the converter assignment. A codec that needs a vendor quirk gets that quirk added to the parser's inputs, never a parallel routing path.
8. Formats crossing into `sound` are ALSA `SNDRV_PCM_FORMAT_*` values and rates are Hz (`58§4`, and the `ops` contract in `crates/kernel/sound/src/ops.rs`). HDA's 20-, 24- and 32-bit widths all travel in a 32-bit container and present as one ALSA format, differing only in the significant-bit count.
9. A BDL entry never crosses a 4 KiB boundary. A period is a whole number of 128-byte blocks. Exactly one entry per period raises the completion interrupt.
10. Stream position comes from the link position register plus a lap count, so the frame position the PCM core reports keeps rising past the end of the buffer.
11. Mixer, capture and jack controls are registered with `sound::elem` from the routing plan. Every control name is the one ALSA userspace looks for; a renamed control is a missing control.
12. A jack change is noticed from an unsolicited response, re-sensed in process context (a sense needs a codec round trip, which an interrupt handler may not take), and published as a control event. While a headphone jack is occupied the fixed outputs are silenced and their external amplifiers disabled.

## 3 Register contract

| Group | Registers |
|---|---|
| Global | `GCAP` `VMIN` `VMAJ` `OUTPAY` `INPAY` `GCTL` `WAKEEN` `STATESTS` `GSTS` `INTCTL` `INTSTS` `WALLCLK` `SSYNC` |
| CORB | `CORBLBASE` `CORBUBASE` `CORBWP` `CORBRP` `CORBCTL` `CORBSTS` `CORBSIZE` |
| RIRB | `RIRBLBASE` `RIRBUBASE` `RIRBWP` `RINTCNT` `RIRBCTL` `RIRBSTS` `RIRBSIZE` |
| Immediate | `IC` `IR` `IRS` |
| Position | `DPLBASE` `DPUBASE` |
| Per stream | `SDCTL` `SDSTS` `SDLPIB` `SDCBL` `SDLVI` `SDFIFOW` `SDFIFOSIZE` `SDFMT` `SDBDPL` `SDBDPU` |

Stream descriptor `n` sits at `0x80 + 0x20 * n`. Descriptors are ordered input block, bidirectional block, output block; `GCAP` gives the three counts. Stream tags are one-based.

## 4 Bring-up order (frozen)

1. Enable memory decode and bus mastering; clear the PCI traffic-class select field.
2. Map BAR0.
3. Assert `GCTL.CRST`, wait for the acknowledgement, settle, deassert, wait, settle. Read `STATESTS` — that is the codec-presence mask.
4. Clear every latched stream, codec-state, response and global interrupt status.
5. Program and start CORB, then RIRB, then allow unsolicited responses.
6. Enable the global and controller interrupts when a vector was obtained.
7. Enumerate the codec, build the routing plan, program pins, amplifiers, selectors and external amplifier enables, and arm jack detection.
8. Reserve the ALSA card, install the operations table, register the controls, publish the nodes.

Reversal on any failure frees exactly what that stage took.

## 5 Public ifc

```rust
// crates/drivers/drv-hda/src/lib.rs
pub struct HdaDriver;                 // impl drv::Driver, matches PCI class 0x040300
pub static HDA_DRIVER: HdaDriver;

// crates/drivers/drv-hda/src/graph.rs
pub trait CodecBus { fn command(&self, nid: u8, verb: u16, payload: u16) -> Option<u32>; }
pub fn parse<C: CodecBus>(bus: &C, addr: u8) -> Option<Codec>;

// crates/drivers/drv-hda/src/generic.rs
pub fn build(codec: &Codec) -> Plan;  // converter assignment + control ownership
```

`CodecBus` is the seam that makes enumeration and the parser hosted-testable: the tests drive them over a recorded node table.

## 6 Test contract

| Behaviour | Where it is pinned |
|---|---|
| Command word field layout, out-of-range refusal | `tests/verb.rs` |
| Response extension, unsolicited flag and tag | `tests/verb.rs` |
| Widget type, channel count, pin bias, amplifier dB scale | `tests/widget.rs` |
| Pin default configuration fields and the fixed-line-out rule | `tests/defcfg.rs` |
| Connection-list slot widths, range markers, null termination | `tests/connlist.rs` |
| Codec enumeration, absent/floating codec, capability fallback | `tests/graph.rs` |
| Pin classification, group promotion, ordering, input sort | `tests/autocfg.rs` |
| Route search: direct preference, terminal nodes, depth limit, control ownership | `tests/paths.rs` |
| Converter assignment, forced pairings, sharing and its cost | `tests/generic.rs` |
| Control naming for every output shape | `tests/ctlname.rs` |
| Which controls a plan publishes and what each points at | `tests/elemkey.rs` |
| Stream format encoding, PCM capability decode | `tests/stream_fmt.rs` |
| BDL construction, boundary split, ring arithmetic | `tests/bdl.rs` |
| CORB/RIRB pointer rules | `tests/ring.rs` |

Acceptance: `make qemu-x86` and `make qemu-arm` with `-device intel-hda -device hda-duplex` both enumerate the codec and publish a second ALSA card with a PCM device and a `Master Playback Volume` control.

## 7 Deviations

Recorded in `scratch/known_issues.md`, each with the Linux behaviour it does not yet match.
