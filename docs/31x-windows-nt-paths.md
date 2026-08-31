# Windows NT path translation

Status: FROZEN  
Frozen: 2026-08-31

The native NT file adapter translates absolute DOS paths into the Windows
namespace exposed by the kernel VFS.  The translation is deterministic and
does not search Linux host paths or load host DLLs.

`C:\\Games\\Example\\data.pak` becomes
`/windows/c/Games/Example/data.pak`.  The `\\??\\` and `\\DosDevices\\`
prefixes are accepted, backslashes become separators, and drive letters are
stored lower-case while the remainder of the name is preserved. Repeated
separators and `.`/`..` components are collapsed lexically; `..` clamps at
the drive root, and embedded NULs are rejected before VFS lookup.

Drive-relative names such as `C:foo` are rejected until the Windows runtime
owns per-drive current directories.  This prevents an incomplete path layer
from silently selecting the wrong file.

Each successful NT file open also claims its requested read, write, and delete
access against its three `FILE_SHARE_*` bits. A conflicting open returns
`STATUS_SHARING_VIOLATION`; the claim belongs to the NT file object and is
released when the final duplicated handle reference closes. Linux file
descriptors and their sharing behavior are unchanged.

`NtCreateFile` accepts all six NT create dispositions. `FILE_CREATE` rejects
an existing name with `STATUS_OBJECT_NAME_COLLISION`; `FILE_OPEN` and
`FILE_OVERWRITE` require an existing name; `FILE_OPEN_IF` and
`FILE_OVERWRITE_IF` create a missing name; overwrite and supersede forms
truncate an existing regular file before returning its handle.

`FILE_DELETE_ON_CLOSE` requires `DELETE` access and is retained by the NT file
object. Duplicated handles therefore share one final-close deletion; ordinary
Linux file descriptors never acquire this behavior.
`FileDispositionInformation` can arm or cancel the same pending deletion on a
handle with `DELETE` access.

`NtLockFile` and `NtUnlockFile` map the native absolute byte ranges onto the
canonical inode record-lock engine. Shared and exclusive locks, immediate
failure, blocking acquisition, conflict status, explicit unlock, and
open-description lifetime all remain owned by that engine; Linux POSIX lock
behavior is not changed.

The hosted syscall suite tests this translation directly; file I/O tests use
the same helper through the native NT adapter.
