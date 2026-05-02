# 31 ELF loader — v2 deferred entries

Carried at freeze 2026-05-02.

## ET_EXEC support

v1 lean = warn + load. Switch to ET_DYN-required once ASLR is mandatory.

## packed / UPX-style binaries

Kernel sees ELF; obfuscated binaries unwrap themselves. Not handled.

## Memory-fd `execve` (`execveat(fd, "", AT_EMPTY_PATH)`)

v1 = yes; required by some modern launchers.
