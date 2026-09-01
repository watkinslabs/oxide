# Windows NT activation-context string lookup boundary

FROZEN 2026-09-01. Dep: 01,02,31fe,52,53. Exposes the validated
`RtlFindActivationContextSectionString` ABI used by Wine's loader.

The boundary rejects unknown flags, a non-null extension GUID, malformed
`UNICODE_STRING` input, and undersized keyed-data output. Because process and
thread activation contexts are not installed yet, valid requests return
`STATUS_SXS_KEY_NOT_FOUND`, matching Wine's lookup result when both scopes
contain no matching section. Manifest/resource parsing and activation-context
stack state remain required.
