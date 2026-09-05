# Windows NT builtin DLL load dispatch

FROZEN 2026-09-03. Dep:`31h`,`31fp`,`31fv`,`52`,`53`. Provides: the Wine
`unix_load_so_dll` dispatch route into the canonical process module owner.

## 1

The fixed Wine request contains an embedded `UNICODE_STRING` at offset zero
and an output module pointer at offset `16`. The Unix-call shim validates the
request address and forwards those exact locations to the process DLL loader.
That owner performs catalog lookup, dependency discovery, PE mapping, import
binding, TLS/entry initialization, PEB loader-list publication, and runtime
module registration as one transaction.

The catalog is the current Oxide representation of Wine builtin modules: the
module bytes are PE32+ images supplied by the Wine runtime package. No second
`.so` catalog or alternate loader path is introduced. A missing module and a
failed image transaction retain the loader's typed NT status.

Exception/unwind and export metadata are parsed for the complete mapped graph
before PEB loader lists, runtime module metadata, or process module references
are published. A metadata failure therefore unmaps the private graph and leaves
existing process state unchanged.

## 2

Hosted dispatch keeps the slot and ABI compilable; target checks compile the
actual route through `nt_loader_dir`. Runtime execution still requires a
process with an installed Wine module catalog and is covered by the existing
dynamic `LdrLoadDll` harness.
