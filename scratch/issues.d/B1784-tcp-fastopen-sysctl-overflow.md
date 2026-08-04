| Status | Class | Sev | Issue | Evidence | Owner |
|---|---|---|---|---|---|
| FIXED pending | DEFECT | low | The `tcp_fastopen_key` sysctl text parser rejected hexadecimal groups longer than eight digits, while Linux `%x` consumes the entire group and stores its low 32 bits. | Linux `net/ipv4/sysctl_net_ipv4.c::sscanf_key` uses `%x` into `u32`; Oxide now consumes every hex digit with `wrapping_shl`, matching truncation. `tcp_fastopen::keys_tests::oversized_hex_groups_wrap_like_linux_sscanf_percent_x`; curated row moves after merge. | B1784-tcp-fastopen-sysctl-overflow |
