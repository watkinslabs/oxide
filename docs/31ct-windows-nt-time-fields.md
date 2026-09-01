# Windows NT time-field conversion

Status: FROZEN
Date: 2026-08-31

The native NTDLL surface owns conversion between Windows `LARGE_INTEGER` time
values and the ABI-defined `TIME_FIELDS` structure. `TIME_FIELDS` is eight
consecutive signed 16-bit values: `Year`, `Month`, `Day`, `Hour`, `Minute`,
`Second`, `Milliseconds`, and `Weekday`.

`RtlTimeFieldsToTime` accepts Gregorian fields with year at least 1601, valid
month/day combinations, hours 0 through 23, minutes and seconds 0 through 59,
and milliseconds 0 through 999. It does not normalize invalid fields. Null or
invalid pointers and failed user copies return `FALSE`; success stores signed
100-nanosecond ticks from the Windows permanent epoch (1601-01-01) and returns
`TRUE`.

`RtlTimeToTimeFields` reads the tick value, writes all eight fields, and derives
the weekday with the same Gregorian arithmetic. Both entry points use checked
user-memory access and preserve the native syscall decoder's x86_64 argument
positions. The contract is covered by decoder tests, native export resolution,
and the installed Wine Notepad graph census.
