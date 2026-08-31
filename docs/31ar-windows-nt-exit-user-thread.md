# Windows NT user-thread exit

Status: FROZEN
Frozen: 2026-08-31

`RtlExitUserThread` routes the current NT personality thread through the
canonical scheduler exit path with the supplied Windows status. It does not
terminate Linux threads or create a separate NT teardown implementation.
