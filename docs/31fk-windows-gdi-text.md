# Windows GDI text foundation

Status: FROZEN  
Frozen: 2026-09-01

`windows-gdi` owns the Win32-facing text façade. Native NT process state owns
device contexts and logical fonts; Linux display drivers remain the display
owner. The adapter does not maintain a second GDI object table.

## 1

- `CreateCompatibleDC` creates a positive-dimension memory device context.
- `CreateFontIndirectW` creates a fixed 64-bit logical-font record containing
  height, width, weight, and italic state.
- `SelectObject` selects a font into a device context and returns the previous
  font handle.
- `GetTextMetricsW` reports height, ascent, descent, average width, maximum
  width, and character width from the selected font or stock font.
- `GetTextExtentPoint32W` measures UTF-16 code units without taking ownership
  of the caller buffer.
- Each memory device context owns a bounded row-major XRGB pixel surface.
- `FillRect` clips to that surface before writing pixels.
- Userspace may upload a validated row-major XRGB raster into a DC; the native
  owner clips the upload before writing the surface.
- Userspace rasterizes TrueType/OpenType glyphs, including UTF-16 surrogate
  decoding and glyph advances, before uploading an XRGB text tile.
- `ExtTextOutW` performs optional opaque background fill, optional rectangle
  clipping, per-code-unit advances, and native tile submission in userspace.
- `DeleteObject` removes device contexts and fonts and clears deleted fonts
  from every context in the process.
- Tagged NT selectors carry the ABI; Linux syscall numbers are not used for
  Windows behavior.

## 2

- Handles are process-local and invalid after deletion.
- Dimensions and font values reject integer-minimum overflow inputs.
- Text buffers are copied and validated before the extent result is written.
- Surface dimensions are bounded before allocation; rectangle writes never
  address pixels outside the owning device context.
- Raster tiles have an independent pixel bound; invalid font bytes, non-finite
  sizes, invalid dimensions, and short source buffers fail before upload.
- Empty text does not upload pixels; opaque empty text still fills its requested
  rectangle.
- Window scanout remains separate display-driver work; GDI owns the raster
  surface and its drawing operations.

## 3

- Hosted GDI tests validate object lifecycle, selection, metrics, extent, ABI
  layouts, and selector values.
- Native IPC tests validate the same owner rules.
- The normal `windows-compat-test` suite and both kernel architecture builds
  cover integration.
