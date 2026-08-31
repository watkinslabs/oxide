# Windows NT Query Section

Status: FROZEN

Date: 2026-08-31

## Contract

Oxide implements the 64-bit `NtQuerySection` `SectionBasicInformation`
class as selector 114. It validates `SECTION_QUERY`, the section handle
type, the output size, and the user buffers, then reports the current
section extent from the native section object. The base address and
allocation attributes are zero because those properties are not stored by
the current section model.

Other information classes return an explicit unsupported information-class
status. The implementation does not expose Linux VMAs or file internals as
Windows section metadata.
