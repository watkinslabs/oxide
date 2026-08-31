# Windows NT Delete Atom

Status: FROZEN

Date: 2026-08-31

## Contract

Wine implements `NtDeleteAtom` by preserving predefined integer atoms and
deleting process-scoped string atoms from the native atom table. Oxide
exposes the 64-bit entry as selector 106 and applies the same distinction:
predefined atoms succeed, while allocated string atoms are removed and their
slots are reusable without changing existing atom identities.

Invalid atom values return `STATUS_INVALID_HANDLE`. The table is owned by the
NT process personality and has no interaction with Linux identifiers.
