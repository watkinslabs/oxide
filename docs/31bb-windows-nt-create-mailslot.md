# Windows NT Create Mailslot

Status: FROZEN

Date: 2026-08-31

## Contract

Wine exposes `NtCreateMailslotFile` for the native mailslot IPC path. Oxide
exposes its 64-bit NTDLL export as selector 105 so the native page has an
explicit ABI entry and the Notepad dependency graph can identify the missing
semantic implementation.

Mailslot objects and their message-delivery semantics are not implemented
yet; the service remains an explicit unsupported NT boundary. It does not
fall through to a Linux file, socket, or other unrelated primitive.
