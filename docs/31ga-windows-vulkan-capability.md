# Windows Vulkan capability boundary

FROZEN 2026-09-04. Dep:`31fk`,`31h`,`45`,`47`,`52`,`53`. Provides: one
versioned native Vulkan admission record for a Windows process.

## 1

- `QueryVulkanCapability` is a tagged NT entry, not a Linux syscall alias.
- The primary DRM driver is the sole owner of render-node, 3D, dimensions, and
  scanout-format state.
- A successful query returns a fixed 24-byte record: version, capability flags,
  maximum width, maximum height, and XRGB/ARGB format mask.
- The Windows Vulkan façade consumes this record before creating a native
  Vulkan instance or handing the device to a translation layer.
- Direct3D, Vulkan command submission, swapchains, and presentation remain
  unsupported until their owning driver contracts exist.

## 2

- The exact record size is required; any other length returns
  `STATUS_INFO_LENGTH_MISMATCH` without writing output.
- No primary card, render node, native 3D capability, usable dimensions, or
  scanout format returns `STATUS_NOT_SUPPORTED`.
- Unsupported capability is never relabeled as software Vulkan or DirectX
  support.
- A failed user copy returns `STATUS_INVALID_PARAMETER`; partial records are
  never published.
- Capability state is read from the current DRM owner on every query; no
  Windows-side shadow registry is maintained.

## 3

- Hosted policy tests cover exact-size ordering, each unsupported prerequisite,
  record encoding, valid consumption, and malformed-record rejection.
- DRM tests cover the driver capability and scanout ownership contracts.
- x86-64 and AArch64 target checks compile the NT dispatch and DRM-backed path.
