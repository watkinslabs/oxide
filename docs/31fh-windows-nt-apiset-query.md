# Windows NT API-set query boundary

FROZEN 2026-09-01. Dep: 01,02,31fg,52,53. Exposes validated
`ApiSetQueryApiSetPresenceEx` handling.

The native boundary validates the counted UTF-16 name and rejects names with
an extension. Until a process API-set namespace is serialized into the PEB,
valid names return success with both `in_schema` and `present` cleared. The
namespace representation, alias target selection, and loader integration
remain required; ordinary DLL catalog lookup must not substitute for them.
