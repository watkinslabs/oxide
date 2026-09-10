# B3630 caption viewport admission

| Status | Branch | Item |
|---|---|---|
| IN-PROGRESS | B3630-paint-region-collapse | KI0859 |

Actual About trace: target/B3630-sizegrip-verification-debug/uart-2337193.log
at71.479-71.564: labels Wine &license/OK measured101x23/17x22; label origins
14,2 and56,3. Valid DCs10008c/100090 then refuse metrics with step=snapshot.
Draw callback returns1 despite no caption submission. Shared DC decoder
previously rejected every nonzero window/viewport origin.

Text snapshots now carry MM_TEXT viewport-minus-window translation from one
shared record. Metrics, logical current position and setters remain available.
TextRequest maps run position and active clipping/opaque rectangle once before
native callback; lengths/advances remain unchanged. Device overflow fails
before mutation. Other unsupported render modes still fail; non-text readers
retain their previous admission contract. No mutable mapping cache added.

Actual ClientBinding regression fails before repair with Codec, exit101:
/tmp/B3630-caption-origin-red.log. Six binding tests pass after repair.
Real native renderer regression rasterizes OK into canonical GdiManager and
compares all130x28 pixels at translated origin with an untranslated baseline;
includes opaque fill, transparent glyph blend and explicit clipping. Removing
translation fails at pixel0,0 (1193046 vs0), exit101:
/tmp/B3630-caption-pixels-control-red.log. Native GDI suite76 tests pass.
Additional codec/coordinate tests cover signed origins, restoration, wide
subtraction, inactive coordinates, overflow and unsupported modes.

Runtime wiring: nt_gdi::text_snapshot_for_current consumes ClientBinding's
mapped snapshot; gdi_raw/kernel.rs::ext_text_out calls TextRequest::translated
before begin. Hosted tests exercise binding and renderer boundaries separately;
they do not execute a full real User32 callback sequence. Both kernel target
checks pass. Both release builds/features/frame gates pass on6afc8cf2a. Static stack gates
retain existing KI0019 failures:336x86/278ARM primary rows, no added/increased
path versus sizegrip-final. No exception or ceiling changed. ELFs:
- target/B3630-caption-final-x86_64.elf SHA0165460b0126ab065219c8d62a58b8c465d7b0ebbe3df0318021e64e1cd44582.
- target/B3630-caption-final-aarch64.elf SHAada5497a84e45ea7c5823cc3f25684b9d8e0e2bac912bab856344dac377aaa35.
Logs /tmp/B3630-caption-{build,feature,stack-x86,stack-arm,frame-x86_64,frame-aarch64}.log.

KI0906: pen shared admission now carries the same translation. Canonical
stroke/fill owner maps endpoints, rectangle edges and point runs before
lease-aware coverage; shared current position stays logical. Joined raw pen
regression initially fails UnsupportedTransform, then8 tests pass. Full IPC
suite1532 passes, including translated rectangle, overflow before mutation,
polyline/polygon and independent viewport/lease origins with visible holes.
Logs /tmp/B3630-caption-underline-{red,green}.log and caption-ipc-green.log.
Full visual acceptance remains open.
Horizontal stripes and Frame refusals remain unexplained. No additional VM.

KI0862 audit: TEXTMEASURE-DROP/TEXTOUT-DROP now fail acceptance with DC,
step, timestamp and repeat count. Prior parser returns PASS on the caption
failure fixture (RED);52 Notepad Python tests pass after wiring. Re-audited
retained latest UART:12 measurement refusals (11 on nonzero DCs) plus two
Frame refusals. The zero-DC failure is retained separately, not suppressed.
Artifacts /tmp/B3630-caption-audit-{red,green}.log and latest run directory
 audit-caption-recheck.md. Caption cause/visual acceptance stay KI0859.

Removing pen device translation produces a pixel assertion failure, exit101
(/tmp/B3630-caption-underline-control-red.log); production source restored.
Frame refusal diagnostics distinguish absent HWND, extent mismatch, retain
failure and replay failure; include frame/window sizes, damage and coverage.
Compositor full suite103 tests passes. Diagnostics do not repair stripes.
