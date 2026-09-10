# Canonical child drawing and paint leases

| Status | Branch | Item |
|---|---|---|
| IN-PROGRESS | B3630-paint-region-collapse | KI-0922 shared containing surface |

Ordinary child DC selection walks canonical parentage to the containing presentation backing. PARENTCLIP affects coverage independently of backing identity. BeginPaint uses existing GetDCEx lease allocation and projection; raster writes reach backing immediately. Paint retention validates an active lease without copying earlier pixels back. Completion clears paint clipping under the existing client lifetime gate and releases the lease; own/class attributes survive. Memory DC storage-copy APIs keep their explicit upload semantics.

Raw BeginPaint/EndPaint, auxiliary erase, nonclient frame and scrollbar call sites use those owners. Scrollbar publication resolves the actual backing association and uses existing acknowledged output accounting; the unused unacknowledged frame sender is removed. No added surface registry, object table or pixel allocation for a lease.

Verification: IPC1560, syscall-library3276, raw-paint30, joined-redraw50, erase2, joined-DC9, projection3, NULL-paint35, output/dispatch149 passed. Source controls independently restore old surface selection and old raw paint implementation, and omit paint-clip release; each fails its intended pixel assertion. Logs `/tmp/B3630-shared-paint-{ipc,final-tests}.log`, `/tmp/B3630-shared-control-{surface-owner,raw-paint-lease,paint-clip-release}.log`. These are hosted ownership/pixel checks, not full desktop acceptance.

Runtime commit b1a9c0feb. Both release builds, feature checks and frame gates passed. Static reports retain334 x86/277 ARM over-budget paths plus the existing exception path each (7664/6368 bytes): no added or increased static path against the PE-identity baseline. Existing KI0019 only; no new exception. Release ELFs target/B3630-shared-paint-{x86_64,aarch64}.elf have SHA256938bf73fd4d6f8b43f35e8e8e5f701ecb0c5f55381af7ca731931379231fc88b /6645512c07727bea0d093e7f6c3cd7db748685a9ec249fd4b7ad36adbc20c78b. Logs /tmp/B3630-shared-paint-build-stack.log and /tmp/B3630-shared-paint-{frame,stack}-arm.log. Debug image prepared and booted; current desktop result below. Retained old VM3672245 exited with launcher status0 at1789043295.1028125; no quit/reboot command was issued. Its exit cause is unconfirmed. Previous compositor-only18869d93e left Open mostly gray; the new kernel improves control painting but fails desktop acceptance.

ARM host sysroot provisioning is recorded in B3630-parent-replay-verification.md (existing KI0691/KI0421). Build recipes retain canonical Cargo configuration and Wine11.16 debug catalog; no runtime-source fork or patch.

Visible run4000812 reached GNOME and one controlled Notepad PE start at51.949s, guestPID955/compositor1005, QEMUPID4000869 was retained after failure, then exited status0 at1789044852.717372 without an issued shutdown. Initial document token and File/Open input passed; Open dialog observation failed. Buttons/labels now render, but file list blank, filename clipped, dialog decoration absent. Screenshot /tmp/B3630-shared-paint-live.png; UART target/B3630-shared-paint-verification-debug/uart-4000812.log; live.json records failure. Save/About/dropdowns not reached. KI0923 records measured filename geometry; op8 caret refused after resize. No evidence yet ties the earlier53.480 null-DC metrics refusal to combo sizing.

Measurement-only PE probe compiled in /tmp/B3630-dc-probe/probe.exe (source/prototype headers local); guest copy failed because QEMU had exited. Probe has not executed. It measures GetDC(NULL), font selection, extent and metrics across release/reacquisition without creating windows. No further boot issued.
