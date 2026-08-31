# Windows NT LdrGetDllDirectory

Status: FROZEN

Date: 2026-08-31

## Contract

`LdrGetDllDirectory` receives a 64-bit Windows `UNICODE_STRING *`. The
foundation loader has no process-local `LdrSetDllDirectory` override, so its
current directory is the empty string. It reports the required terminating
UTF-16 NUL (`Length == sizeof(WCHAR)`), writes the NUL when the caller's
`MaximumLength` is sufficient, and returns `STATUS_BUFFER_TOO_SMALL` when it
is not. Invalid descriptors or buffers return `STATUS_INVALID_PARAMETER`.

The adapter performs all descriptor and string writes through uaccess and is
available only through the native 64-bit NT NTDLL stub, selector 99. It does
not consult or mutate Linux loader environment state.
