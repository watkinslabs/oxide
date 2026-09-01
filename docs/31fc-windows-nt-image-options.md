# Windows NT image execution options query

FROZEN 2026-08-31. Dep: 01,02,31fb,52,53. Exposes the validated `LdrQueryImageFileExecutionOptions` ABI.

The current native process has no mounted Windows registry personality, so the query validates the caller's key descriptor and returns the canonical missing-key status. Registry-backed option storage remains required before configured IFEO values can be observed.
