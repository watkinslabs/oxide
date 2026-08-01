/// `IPPROTO_IPV6` option state and validation — the ungated owner of every decision
/// the slot-54/55 shims make at this level (option numbers, operand widths,
/// value windows, capability ladders, errno ordering). The shims parse,
/// validate through this module, call one work function, and encode.

/// Per-socket `IPPROTO_IPV6` option state.
#[derive(Debug, Default)]
pub struct Ipv6Opts {}
