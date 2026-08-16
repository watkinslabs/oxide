// Sizes of the per-interface priority tables and of the demux table.

/// One entry per priority code point.
pub const INGRESS_MAP_LEN: usize = 8;
/// Index mask applied to a code point before it reaches the ingress table.
pub const INGRESS_MAP_MASK: u32 = (INGRESS_MAP_LEN as u32) - 1;

/// Egress buckets, selected by the low bits of the transmit priority. Each
/// bucket holds an exact-match list, so two priorities sharing a bucket stay
/// distinct.
pub const EGRESS_BUCKETS: usize = 16;
/// Bits of a transmit priority that pick the egress bucket.
pub const EGRESS_BUCKET_MASK: u32 = (EGRESS_BUCKETS as u32) - 1;
