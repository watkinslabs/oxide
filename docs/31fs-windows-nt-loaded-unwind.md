# Windows NT loaded builtin unwind metadata

FROZEN 2026-09-03. Dep:`31fr`,`31fq`,`31h`,`31v`,`52`,`53`. Provides: the
single publication record consumed by the builtin ELF unwind owner.

## 1

After PT_LOAD placement, the ELF loader publishes at most one `.eh_frame`
view for the image. Publication succeeds only when the section is allocated,
file-backed, and wholly contained in the virtual and file ranges of a
PT_LOAD. The selected load bias translates its virtual address; no loader
component chooses a second address or copies a shadow metadata buffer.

The record retains the image virtual bounds and section bytes. A runtime FDE
lookup must first constrain its instruction pointer to those bounds, then use
the bounded section reader from `31fq`.

## 2

Missing unwind data is a valid image state. A malformed section table or a
named section that cannot be reconciled with PT_LOAD placement is an image
format error. This follows the ELF loader's distinction between metadata
validation and mapping, and keeps publication independent of PE unwind data.

Hosted tests cover successful bias translation and rejection of a section
outside the loaded file range. Both target checks compile the same owner.
