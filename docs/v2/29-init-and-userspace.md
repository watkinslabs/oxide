# 29 Init + Userspace bring-up — v2 deferred entries

Carried at freeze 2026-05-02.

## systemd as PID 1

v2.

## OpenRC vs custom init

v1 = custom init (minimal). "service" is reserved as a v1 keyword.

## musl vs glibc

v1 = musl as primary libc.

## Static vs dynamic for v1 binaries

v1 = static (simpler boot; no dynlink bring-up). One demo binary dynamically linked to validate `ld-oxide`.
