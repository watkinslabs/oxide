| Status | Class | Sev | Issue | Evidence | Owner |
|---|---|---|---|---|---|
| CLAIMED | DEFECT | low | `PTRACE_SETSIGINFO` accepted an unknown `(si_signo, si_code)` with nonzero bytes beyond the kernel siginfo prefix, silently losing those bytes instead of returning `E2BIG`. | Shared signal copy-in drops bytes 48..127; ptrace validates the full 128-byte user record. | B1908-ptrace-siginfo-expansion |
