# Windows NT builtin DWARF CFA execution

FROZEN 2026-09-03. Dep:`31ft`,`31fs`,`31fp`,`31v`,`52`,`53`. Provides: bounded
register recovery for the FDE instruction stream.

## 1

The evaluator applies the core DWARF call-frame rules used by Wine builtin
modules: CFA register/offset changes, register offsets, same/undefined rules,
restore, and bounded remember/restore state. It stops at the requested code
delta and reads saved words only through the caller's range-checked reader.

`evaluate_frame` now consumes the validated CIE+FDE program produced by the
DWARF owner, preserving the same alignment factors and instruction ordering
through the execution boundary. Expressions, register indirection, and unsupported encodings return explicit
errors. A missing saved return address is not converted into a guessed frame.
The result is a new context value; the evaluator does not mutate the caller's
context or access process memory itself.

## 2

The shared ABI remains x86-64 Windows register numbering for this execution
surface, while the no-std module compiles in both target checks. PE
`UNWIND_INFO` and ELF DWARF remain separate metadata owners.

Hosted tests cover CFA/RIP recovery, unreadable stack words, expression
rejection, and execution through a validated CIE+FDE program. Runtime dispatch
still needs to connect this evaluator to the validated Wine Unix request and
published loaded-image records.
