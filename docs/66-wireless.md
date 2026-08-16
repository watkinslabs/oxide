# 66 — Wireless (cfg80211, mac80211, nl80211)

DRAFT 2026-08-16. Dep:`01`,`02`,`06`,`07`,`08`,`13`,`15`,`19`,`22`,`25`,`34`,`35`,`52`,`53`.

## 1 Scope

802.11 station, access-point and monitor operation on a machine whose only
network hardware is a radio. Three layers, matching the reference split:

| Layer | Crate | Owns |
|---|---|---|
| cfg80211 | `crates/kernel/wireless` | radio registry, channels, regulatory, scan/BSS cache, connect state machine, keys, station reporting, the nl80211 family |
| mac80211 | `crates/kernel/mac80211` | interfaces, RX/TX handler chains, MLME, station table, link ciphers, aggregation, power save, rate control |
| driver | `crates/drivers/drv-mac80211-hwsim` | virtual radios over a simulated medium |

Out of scope here: the supplicant, the key-exchange protocol, and the
authentication server. Those are userspace (`29a`); the kernel's obligation is
the surface they drive.

## 2 Why nl80211 is the whole contract

`wpa_supplicant`, `iw` and NetworkManager speak nl80211 and nothing else. A
radio that is not registered in the cfg80211 registry does not exist to them
however well its driver works, and a command whose attributes are laid out
differently than the reference lays them out is not "close" — it is a parse
failure in a program that then reports no wireless hardware.

The family registers through the existing generic-netlink owner
(`crates/kernel/netlink/src/genetlink`). There is no second family registry.
Each command supplies its own handler through `GenlOp::doit`/`dumpit`, which is
how the reference's `genl_ops` works and what keeps the dispatcher from having
to know every family by name.

## 3 Layer boundaries

1. `wireless` depends on `netlink`, `syscall` and `sync`. It does NOT depend on
   `net`: cfg80211 in the reference does not own a network device, and a
   dependency the other way would make the radio registry unreachable from a
   host build.
2. `mac80211` depends on `wireless`, `net` and `crypt`. It owns the only
   `impl Cfg80211Ops` a softmac driver needs and the only `net::NetDev` a
   wireless interface presents.
3. A driver depends on `mac80211` and never on `wireless` directly for its
   operations. A fullmac driver would implement `Cfg80211Ops` itself; none
   exists yet.
4. Lock order is `Wiphy` (136) → `Sta80211` (137) → `Socket` (140), per `06§3.6`.
   A station record is never taken before its interface, and neither is held
   across the hand-off into the network stack.

## 4 Objects

| Object | Meaning | Identifier |
|---|---|---|
| wiphy | one radio | `u32` index; `phy<n>` |
| wdev | one virtual interface on a radio | `u64`, radio index in the top half |
| netdev | the interface the rest of the stack sees | Linux ifindex, only for types that have one |

`P2P_DEVICE`, `NAN` and `PD` interfaces carry no netdev, which is why every
nl80211 command accepts a wireless identifier and only some accept an
interface index.

## 5 Capability advertisement is immutable

A radio's bands, channels, cipher suites and interface-mode mask are decided at
registration and never change afterwards. Configuration (`WiphyConfig`) is the
only writable half. A caller able to rewrite the advertisement could make it
disagree with what the driver will accept, and userspace plans a whole
connection from the advertisement.

## 6 Regulatory

Frequencies are held in kHz and power in millibel units end to end: rounding a
range to megahertz can widen it past what a rule permits, and two bands place
channels off the megahertz grid.

**Arbitration.** Four initiators, in the reference's precedence:

| New request | Against | Result |
|---|---|---|
| core | anything | adopt if the code changes |
| user | core / driver / user | adopt; ignore once an intersection is in force |
| user | country element | intersect |
| user | cellular advice | ignore |
| driver | core | adopt |
| driver | anything else | intersect |
| country element | user, driver, core | adopt (first one only) |
| country element | another radio's country element | ignore |
| country element | cellular advice | ignore |

**The rule that matters.** A country element from an access point never
overrides a domain the user set. An access point can claim any country; a
station that believed it would transmit where its owner may not.

**Projection.** A channel no rule covers is `DISABLED`, not merely restricted.
A channel left enabled because no rule mentioned it is an out-of-band
transmission. Every restriction is recomputed from the domain on each apply, so
a domain change that lifts a restriction leaves no flag behind.

**Intersection is one-directional.** No intersection may permit what neither
input permitted: ranges narrow, power ceilings take the minimum, and
restrictions take the union.

## 7 Scan and the BSS cache

One network on one channel is one entry however many frames arrive for it. An
entry holds BOTH element sets: a probe response is the only place a hidden
network's name appears, so a later beacon must not overwrite the elements that
carry it.

- Expiry: `66§7` uses the reference's 30-second window from last-heard.
- An entry a caller holds is not expired out from under it. The connect path
  resolves a network and uses it across several steps.
- A radio runs at most one scan. A second request while one is live is `EBUSY`,
  not a queue.
- A driver refusal must clear the stored scan state; a state left behind makes
  every later scan `EBUSY` forever.

## 8 The connect state machine

Exactly ONE terminal outcome reaches userspace per connect attempt: a connect
result or a disconnect, never both and never neither. A supplicant that gets
two acts twice; one that gets none waits forever.

Steps: scanning → authenticate → associate → connected, with a timeout and a
local-disconnect path out of each. A local disconnect before the authentication
exchange started sends no frame — there is nothing to deauthenticate from.

An `AUTOMATIC` authentication type tries the open algorithm first because every
network accepts it, and the shared-key algorithm exactly once if that is
refused. A pinned algorithm is never retried with another.

## 9 Keys

Validation order is ABI, because several checks reject the same request with
DIFFERENT errnos and userspace branches on which it gets:

1. index range (depends on what the radio advertised — see below)
2. pairwise/group addressing
3. per-cipher index rules
4. interface-type cipher restriction
5. key length
6. sequence length
7. cipher advertised by the radio

Then, separately, whether the interface is in a state to hold a key at all —
which is `ENOLINK` for an unassociated client, not `EINVAL`.

**Index space.** 0–3 data, 4–5 management integrity, 6–7 beacon integrity. A
radio with no integrity cipher has no index above 3; only one advertising
beacon protection reaches 7. A pairwise key never exceeds 3 whatever the radio
says, and without extended key id it is index 0 alone.

**An integrity group cipher can never be a pairwise key.** Accepting one would
install a management-frame integrity key where a data key belongs.

**A default must point at an installed key**, and removing a key clears any
default that pointed at it. A default pointing at nothing sends frames in the
clear.

**Disconnecting forgets the peer's keys.** A key left installed for a peer this
interface is no longer associated to would encrypt the first frames of the NEXT
association with the old key.

## 10 mac80211

**Receive chain**, in order: length and frame-control sanity → monitor delivery
→ decryption → defragmentation → duplicate detection → block-ack reordering →
management dispatch → control frames → data conversion → delivery.

**Transmit chain**: sequence assignment → fragmentation → encryption → rate
selection → queue by access category → driver.

**Controlled port.** Before the port is authorized, only the authentication
protocol EtherType may leave the interface. Everything else is refused.

**Management frame protection.** On a protected link an UNPROTECTED
deauthenticate or disassociate must NOT tear the link down. It is reported
under its own command and the association is kept. Acting on it is exactly the
attack the protection exists to stop.

**Replay detection** is per receive packet number, per TID on a QoS link. A
single counter shared across TIDs silently accepts replays.

**Block-ack window** arithmetic is modulo 4096 and is the highest-value test
target in the subsystem: an off-by-one stalls a link instead of failing
loudly.

## 11 Events

| Event | Group | Raised on |
|---|---|---|
| `NEW_WIPHY` / `DEL_WIPHY` | `config` | radio registration |
| `NEW_INTERFACE` / `DEL_INTERFACE` | `config` | interface lifecycle |
| `TRIGGER_SCAN`, `NEW_SCAN_RESULTS`, `SCAN_ABORTED` | `scan` | scan lifecycle |
| `CONNECT`, `DISCONNECT`, `ROAM`, `PORT_AUTHORIZED` | `mlme` | connect outcome |
| `AUTHENTICATE`…`DISASSOCIATE`, `UNPROT_*` | `mlme` | management exchange |
| `NEW_STATION` / `DEL_STATION` | `mlme` | access-point membership |
| `MICHAEL_MIC_FAILURE`, `NOTIFY_CQM` | `mlme` | link events |
| `FRAME`, `FRAME_TX_STATUS` | unicast / `mlme` | registered frames |
| `REG_CHANGE` | `regulatory` | domain change |

Group choice is contract. A supplicant subscribes to `mlme` and `scan` and not
to `config`; a connection event on `config` reaches nobody that cares.

A received management frame goes ONLY to the port that registered for its
subtype, and to that port once even when two registrations match. Broadcasting
it would hand every listener frames addressed to another.

**Ordering.** A driver report updates core state and THEN raises the event, so
a listener woken by the event reads state that already agrees with it.

## 12 The virtual radio

`mac80211_hwsim` registers N software radios over a shared medium: a frame
transmitted by one is delivered to every other radio tuned to the same channel.
It is the caller that keeps this subsystem from being machinery nothing calls
(`05`), and it makes the whole stack exercisable hosted, with no hardware and
no boot.

## 13 Test contract

Every one of these is hosted and runs in an UNGATED module (`53`, and the
phantom-test rule):

| Area | Must pin |
|---|---|
| frames | header width per type; the four DS-bit address maps; a frame shorter than its own header is refused |
| elements | a declared length past the end stops the walk; a duplicate id keeps the first; a zero-length SSID is present-and-empty |
| channels | the four number/frequency rules; a wide definition must contain its primary |
| regulatory | intersection never widens; a restriction in either side survives; an uncovered channel is disabled; the arbitration table above |
| country element | an operating triplet is not a subband; 5 GHz subbands step by four channel numbers |
| BSS cache | a beacon does not overwrite a probe response's name; holds defeat expiry; one association mark at a time |
| connect | exactly one terminal outcome per attempt, from every reachable step |
| keys | the validation order above; every cipher's key and sequence length; a default never outlives its key |
| ciphers | round-trip; a flipped bit anywhere fails; published vectors for each |
| replay | equal and lower packet numbers rejected; counters independent per TID |
| aggregation | window edges across the sequence wrap in both directions |
| nl80211 | the errno for each refusal AND the order between two applicable refusals |
| end to end | two virtual radios associate and exchange a data frame |

Each area additionally requires a positive control: reintroduce the defect,
confirm RED, restore, confirm GREEN.

## 14 OQ

1. Fullmac path: no driver needs it yet. Add when one does, not before.
2. Mesh and the neighbour-awareness protocol are advertised in the interface
   type space but have no state machine; both are in scope for this spec and
   not yet written.
3. Scheduled scan and wake-on-wireless have attribute space reserved and no
   implementation.
