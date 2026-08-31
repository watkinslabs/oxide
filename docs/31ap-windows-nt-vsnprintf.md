# Windows NT `_vsnprintf`

Status: FROZEN
Frozen: 2026-08-31

The native NTDLL surface provides the four-argument `_vsnprintf` entry using
the Windows x86-64 register-save-area `va_list` convention. Formatting is
bounded by the caller's destination length and the kernel's input/output
limits; user buffers are accessed only through the native user-copy boundary.
Supported conversions are strings, narrow character, signed/unsigned decimal,
hexadecimal, pointers, width, precision, and literal percent.
