# Windows NT builtin FDE lookup

FROZEN 2026-09-03. Dep:`31fq`,`31fs`,`31v`,`52`,`53`. Provides: instruction
pointer lookup for published builtin ELF call-frame records.

## 1

The lookup owner walks the published `.eh_frame` records, resolves each FDE's
CIE augmentation, and decodes the FDE start and range with the declared
`DW_EH_PE` encoding. It returns a bounded record only when the instruction
pointer is within `[start, start + length)`.

Missing FDE coverage is a normal lookup result. Truncated records, missing
CIE links, unsupported encodings, and arithmetic overflow are format errors;
they do not fall through to an unrelated PE unwind record.

## 2

The returned record contains its code range and original bounded instruction
bytes. Register-rule/CFA execution remains owned by the runtime context
layer, preserving the distinction between metadata lookup and context
mutation required by `31fp`.

Hosted tests cover CIE `zR` decoding, covered and uncovered instruction
pointers, and malformed data. Both architecture checks compile the shared
lookup path.
