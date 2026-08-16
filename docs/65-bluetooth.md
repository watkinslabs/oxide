# 65 Bluetooth

DRAFT. Dep:`01`,`02`,`07`,`08`,`15`,`16`,`19`,`25`,`27`,`28`,`35`,`52`,`53`. Provides:HCI core, `AF_BLUETOOTH` family, L2CAP, SMP, RFCOMM, SCO, management interface, transport contract.

## 1 Scope

Wireless keyboards, mice and headsets. The surface a Bluetooth userspace
(`bluetoothd`, `btmon`, `btmgmt`, `rfcomm`) speaks, in full: no tier, no subset,
no deferral (`02`, Discipline rule 3).

## 2 Invariants (frozen)

1. A peer is `(address, address type)`. A BR/EDR address and an LE address with
   the same six bytes are different peers with different keys.
2. The host holds at most one HCI command in flight. A completion restores the
   allowance to exactly one; it never increments.
3. A frame whose declared length disagrees with the bytes present is refused,
   never parsed short.
4. Event decode is total and separate from event apply: a malformed event
   changes no state.
5. A channel is admitted only when its link already satisfies the security level
   the channel requires.
6. Controller indexes are allocated lowest-free, so a controller keeps its name
   across a reset.
7. One transport contract (`4`). A new bus is a new implementation of it and no
   change above.

## 3 Layers

| Layer | Owner | Carries |
|---|---|---|
| Transport | driver crate | whole H:4 frames, both directions |
| HCI core | `crates/kernel/bluetooth/src/hci` | framing, credits, events, connections, setup |
| L2CAP | `src/l2cap` | channels, signalling, config, ERTM, LE credits |
| SMP | `src/smp` | pairing, key derivation, key store, level sufficiency |
| RFCOMM | `src/rfcomm` | multiplexer, DLCs, credits, TTY binding |
| SCO | `src/sco` | synchronous links, parameter negotiation |
| Management | `src/mgmt` | the command and event surface `bluetoothd` speaks |
| Sockets | `src/sock` | `AF_BLUETOOTH` and its four protocols |

## 4 Transport contract

A transport implements `hci::transport::HciTransport`: `open`, `close`, `send`
of one whole H:4 frame, `bus`, `driver_name`. It carries bytes and knows nothing
of their contents.

Byte-oriented buses reassemble with `hci::packet::H4Decoder` before handing a
frame up. An unknown packet-type byte desynchronises the stream permanently —
there is no framing to resynchronise against — so the decoder latches an error
rather than guessing a boundary.

## 5 Command flow

Credit accounting per `2` invariant 2. Two deadlines, mutually exclusive by
construction: a command drawing no answer within `HCI_CMD_TIMEOUT_MS`, and an
event reporting a zero allowance that is never restored within
`HCI_NCMD_TIMEOUT_MS`.

## 6 Setup sequence

Four stages, each a fixed command order gated on capability words the previous
stage read. BR/EDR capability is stated NEGATIVELY in the feature mask: a
controller reporting nothing is classic-only. An unconfigured controller — one
with no assigned address — stops after stage one.

Optional stage-four commands are screened against the supported-command bitmap:
a command whose bit is clear draws a refusal, and a refusal during setup is
indistinguishable from a broken controller.

## 7 Sockets

`AF_BLUETOOTH` = 31, registered through the existing family owner
(`crates/kernel/net`, `crates/kernel/socket`). No second family registry.

| Protocol | Value | Address |
|---|---|---|
| `BTPROTO_L2CAP` | 0 | `sockaddr_l2` |
| `BTPROTO_HCI` | 1 | `sockaddr_hci` |
| `BTPROTO_SCO` | 2 | `sockaddr_sco` |
| `BTPROTO_RFCOMM` | 3 | `sockaddr_rc` |

Raw HCI sockets bind a channel: raw, user, monitor, control, logging. A fresh
raw socket's filter passes nothing — a socket receiving everything by default
would leak another process's traffic.

## 8 Monitor

Every frame in either direction, and every controller appearing or
disappearing, becomes one monitor record: a six-byte header then the frame
WITHOUT its H:4 prefix, which the record's opcode already names.

## 9 Security

Level ordering `SDP < LOW < MEDIUM < HIGH < FIPS`. Sufficiency depends on the
key type AND the encryption key size, not on the level number alone. An
unauthenticated key never satisfies `HIGH`.

Peer public keys are validated before use: not the point at infinity, on the
curve, coordinates below the field prime.

## 10 Test contract (frozen)

1. Every PDU round-trips encode then decode; every truncated and over-long form
   is refused.
2. Streaming reassembly of a frame split one byte at a time yields it exactly
   once.
3. A repeated command completion does not inflate the credit.
4. Each setup stage's command list matches the capability words that gate it,
   and no stage repeats a command.
5. Pairing-method selection is checked for the whole matrix, both legacy and
   secure connections, with every override.
6. Crypto primitives are checked against published vectors.
7. Flow control: credit exhaustion blocks, a grant releases, an over-grant is
   refused.
8. Every claim carries a positive control — the defect reinstated, the check
   RED, restored, GREEN.

## 11 Cross-spec

`25§6` sockets, `27` security, `28` TTY for the RFCOMM binding, `35` drivers,
`52§5` ownership, `53` syscall layering.
