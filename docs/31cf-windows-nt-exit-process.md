# Windows NT process exit

Status: FROZEN
Date: 2026-08-31

`RtlExitUserProcess` enters the existing Linux-shaped group-exit owner with
the supplied Windows status. Native personality validation happens before the
handoff; Linux `exit_group` and ordinary thread exit remain separate paths.
