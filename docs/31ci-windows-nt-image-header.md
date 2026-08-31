# Windows NT PE image header probe

Status: FROZEN
Date: 2026-08-31

`RtlImageNtHeader` validates the DOS and NT signatures through fault-
recovering user reads and returns the NT-header address inside the supplied
image. Invalid or inaccessible images return null; full PE parsing remains
owned by the shared PE parser.
