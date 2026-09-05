# Windows Vulkan surface and present boundary

FROZEN 2026-09-04. Dep:`31ga`,`31fj`,`31fl`,`47`,`52`,`53`. Provides the
userspace WSI admission and lifecycle contract consumed by a Windows Vulkan
loader or a Direct3D translation layer.

## 1 Ownership

- DRM owns device, render-node, dimensions, scanout formats, and presentation
  capability facts.
- The NT capability record is the only device snapshot crossing into the
  Windows personality.
- user32's process-scoped window owner supplies the canonical window identity;
  a present request carries that identity together with the Vulkan device,
  queue, and resource identities.
- The userspace Vulkan façade owns surface admission and the present lifecycle;
  it stores no alternate device capability registry.

## 2 Admission

- A surface is admitted only when the device is ready, the surface is alive,
  presentation is supported, dimensions are nonzero and within the native
  bounds, and the requested format is in the native format mask.
- Unsupported device, surface, format, and dimension states return
  `Unsupported`; they are never downgraded to software presentation.
- A valid surface moves `Ready` → `Acquired` → `Ready` for each submission.
  `Present` without `Acquire`, duplicate `Acquire`, and operations after
  `Lost` return `InvalidState`.
- `Acquire` rejects any window, owner, device, queue, or resource identity that
  does not match the admitted record; it does not reserve the surface first.
- `Present(Submitted)` commits the reservation. `Present(Rejected)` returns
  `QueueRejected` and restores `Ready`, so a failed queue handoff cannot strand
  ownership in the session.
- Device removal or WSI loss moves the session to terminal `Lost`.

## 3 Translation boundary

Win32 surface creation, surface capability/present-support queries, and queue
presentation remain Vulkan loader operations. DXVK and VKD3D-Proton consume
this boundary; this contract does not implement Direct3D or fabricate Vulkan
commands.

## 4 Tests

- The userspace probe consumes the native NT capability record and executes one
  admitted acquire/present cycle.
- Hosted tests cover admission failures, owner/device/queue/resource identity,
  acquire/present ordering, explicit queue rollback, repeated cycles, and
  terminal surface loss.
- A positive-control mutation of any required admission or lifecycle condition
  makes the focused test suite fail.
- x86-64 and AArch64 GNU userspace builds compile the same ABI and state
  machine.
