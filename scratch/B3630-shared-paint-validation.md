# Canonical child drawing and paint leases

| Status | Branch | Item |
|---|---|---|
| IN-PROGRESS | B3630-paint-region-collapse | KI-0922 shared containing surface |

Ordinary child DC selection walks canonical parentage to the containing presentation backing. PARENTCLIP affects coverage independently of backing identity. BeginPaint uses existing GetDCEx lease allocation and projection; raster writes reach backing immediately. Paint retention validates an active lease without copying earlier pixels back. Completion clears paint clipping under the existing client lifetime gate and releases the lease; own/class attributes survive. Memory DC storage-copy APIs keep their explicit upload semantics.

Raw BeginPaint/EndPaint, auxiliary erase, nonclient frame and scrollbar call sites use those owners. Scrollbar publication resolves the actual backing association and uses existing acknowledged output accounting; the unused unacknowledged frame sender is removed. No added surface registry, object table or pixel allocation for a lease.

Verification: IPC1560, syscall-library3276, raw-paint30, joined-redraw50, erase2, joined-DC9, projection3, NULL-paint35, output/dispatch149 passed. Source controls independently restore old surface selection and old raw paint implementation, and omit paint-clip release; each fails its intended pixel assertion. Logs `/tmp/B3630-shared-paint-{ipc,final-tests}.log`, `/tmp/B3630-shared-control-{surface-owner,raw-paint-lease,paint-clip-release}.log`. These are hosted ownership/pixel checks, not full desktop acceptance.

Both target-gated kernel checks passed before final scrollbar publication cleanup. Final release/frame/stack checks running; no new kernel installed yet. Retained old VM3672245 exited with launcher status0 at1789043295.1028125; no quit/reboot command was issued. Its exit cause is unconfirmed. Previous compositor-only18869d93e left Open mostly gray; the new kernel change remains unverified in the desktop.

ARM host sysroot provisioning is recorded in B3630-parent-replay-verification.md (existing KI0691/KI0421). Build recipes retain canonical Cargo configuration and Wine11.16 debug catalog; no runtime-source fork or patch.
