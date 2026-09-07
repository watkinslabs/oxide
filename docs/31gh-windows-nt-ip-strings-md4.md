# Windows NT IP address strings and MD4

FROZEN 2026-09-06. Dep: `01`,`02`,`31am`,`31h`,`52`,`53`. Provides the native NTDLL IP address text, status translation and MD4 digest exports the installed 64-bit Wine Notepad module closure imports.

## 1

Twenty exports, all six-argument stubs on the synthetic NT runtime page, routed by `nt_ip_string`, `nt_md4` and `nt_rtl`.

| Export | Answer | Operands |
|---|---|---|
| `RtlIpv4StringToAddress{A,W}` | NTSTATUS | text, strict, terminator out, 4-byte address out |
| `RtlIpv4StringToAddressEx{A,W}` | NTSTATUS | text, strict, address out, network-order port out |
| `RtlIpv4AddressToString{A,W}` | pointer to the produced terminator | 4-byte address, buffer |
| `RtlIpv4AddressToStringEx{A,W}` | NTSTATUS | address, network-order port, buffer, size in/out |
| `RtlIpv6StringToAddress{A,W}` | NTSTATUS | text, terminator out, 16-byte address out |
| `RtlIpv6StringToAddressEx{A,W}` | NTSTATUS | text, address out, scope out, port out |
| `RtlIpv6AddressToString{A,W}` | pointer to the produced terminator | address, buffer |
| `RtlIpv6AddressToStringEx{A,W}` | NTSTATUS | address, scope, port, buffer, size in/out |
| `RtlNtStatusToDosErrorNoTeb` | Win32 error | NT status |
| `MD4Init`, `MD4Update`, `MD4Final` | none | 104-byte context record, message run |

## 2

IPv4 text is one to four components separated by `.`. A component takes an `0x` hex prefix or a leading-zero octal prefix; the strict form rejects both and requires four components. Component accumulation is 32-bit wrapping and fails only when a step decreases the running value, so a run that saturates at the ceiling keeps scanning. Fewer than four components pack the trailing value into the remaining octets: three components allow 16 bits in the last, two allow 24, one supplies all four octets. A `:port` suffix parses in every form, must be non-zero, must fit 16 bits, and must end the string; only the extended entries store it, in network order.

Where the caller supplies a terminator, the parse reports the index it stopped at and trailing text is not an error; where it does not, trailing text fails. A parse that reaches the address store keeps the stored address even when the port that follows is rejected.

## 3

IPv6 text is colon-separated hexadecimal groups with at most one `::` elision, an optional trailing dotted quad, and — in the extended form only — a bracketed host with `%scope` and `]:port` suffixes. Group values come from the wide unsigned-long conversion clamped to `0x7fffffff`. A group longer than four digits, or an embedded quad component longer than three digits or above 255, fails. A trailing group may carry an `0x` prefix and overrun four digits; that form reports the prefix letter as the stop and the extended entries reject it. An elision that lands with fourteen bytes already parsed consumes nothing further.

## 4

IPv6 rendering elides the longest zero run of two or more groups, ties going to the first. The low 32 bits print as a dotted quad when the address is the mapped, compatible or tunnel form. A non-zero scope appends `%scope`; a non-zero port brackets the address and appends `]:port`. Both extended renderers report the required byte count including the terminator and answer `STATUS_INVALID_PARAMETER` when the caller's size is short; the IPv4 extended renderer requires strictly more than the produced length. The plain renderers assume the caller's fixed buffer, clear its last unit, and answer the address of the produced terminator.

## 5

The narrow entries widen through a fixed scratch — 32 units for IPv4, 128 for IPv6 — whose last unit is cleared, so a longer string loses everything from that unit on and the reported terminator is a byte index into the caller's string. The wide entries take the caller's string as it stands.

## 6

`RtlNtStatusToDosErrorNoTeb` is the translation of `31am` without the thread-block record: success and customer-bit statuses pass through, the alternate severity nibble normalizes onto the error severity, the three facilities that already carry a Win32 error answer with their low word, and an unmapped status answers `ERROR_MR_MID_NOT_FOUND`.

## 7

MD4 accumulates into a 104-byte context record — four chaining words, a two-word bit count, a 64-byte block, a 16-byte digest — read and written through the user boundary on every call. `MD4Final` pads with `0x80`, zero-fills to the length field, appends the bit count little-endian, compresses, and publishes the digest without reinitializing. The exports return nothing.

## 8

Decision logic — component scanning, packing, elision, rendering, status translation, digest state — lives in ungated modules under `crates/kernel/syscalls/src/nt_ip_string/`, `nt_md4/` and `nt_status_dos.rs`, tested hosted against the reference contract. The kernel-only `dispatch` children fetch and store operands only.
