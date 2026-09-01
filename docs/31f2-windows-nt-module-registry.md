# Windows NT native PE module registry

FROZEN 2026-08-31. Dep: 01,02,31f1,52,53. Publishes validated PE image ranges and exception-directory metadata from the loader to the NT unwind and loader boundaries.

Registry ownership follows the process address space identity. Lookups return only registered image metadata; arbitrary VMA starts are not treated as PE module bases.
