# 28 TTY + PTY — v2 deferred entries

Carried at freeze 2026-05-02.

## ldisc plugin slot (SLIP/PPP/uart-like)

Deferred to v2 (no dial-up support in v1).

## Console multiplexing

`/dev/console` may be redirected to first tty. v1 supports via `console=tty1` cmdline.

## Wide-char / UTF-8 in canonical edit

v1 treats bytes; userspace handles UTF-8 width semantics.
