//! Verdict codes and the register file's ABI shape.

// --- nftables-internal verdicts (negative, never leave the interpreter) ---

pub const NFT_CONTINUE: i32 = -1;
pub const NFT_BREAK:    i32 = -2;
pub const NFT_JUMP:     i32 = -3;
pub const NFT_GOTO:     i32 = -4;
pub const NFT_RETURN:   i32 = -5;

// --- base netfilter verdicts ---

pub const NF_DROP:   i32 = 0;
pub const NF_ACCEPT: i32 = 1;
pub const NF_STOLEN: i32 = 2;
pub const NF_QUEUE:  i32 = 3;
pub const NF_REPEAT: i32 = 4;
pub const NF_STOP:   i32 = 5;

pub const NF_VERDICT_MASK:  i32 = 0x0000_00ff;
pub const NF_VERDICT_QBITS: u32 = 16;
pub const NF_VERDICT_FLAG_QUEUE_BYPASS: i32 = 0x0000_8000;

/// Verdict word carrying a queue number. # C: O(1)
pub const fn nf_queue_nr(num: u16) -> i32 { ((num as i32) << NF_VERDICT_QBITS) | NF_QUEUE }

/// Queue number carried by a verdict word. # C: O(1)
pub const fn nf_verdict_qnum(code: i32) -> u16 { (code >> NF_VERDICT_QBITS) as u16 }

// --- data types a register may hold ---

pub const NFT_DATA_VALUE:          u32 = 0;
pub const NFT_DATA_VERDICT:        u32 = 0xffff_ff00;
pub const NFT_DATA_RESERVED_MASK:  u32 = 0xffff_ff00;
pub const NFT_DATA_VALUE_MAXLEN:   usize = 64;

// --- registers ---

pub const NFT_REG_VERDICT: u32 = 0;
pub const NFT_REG_1:       u32 = 1;
pub const NFT_REG_2:       u32 = 2;
pub const NFT_REG_3:       u32 = 3;
pub const NFT_REG_4:       u32 = 4;
pub const NFT_REG_MAX:     u32 = 4;

pub const NFT_REG32_00:    u32 = 8;
pub const NFT_REG32_15:    u32 = 23;
pub const NFT_REG32_MAX:   u32 = 23;

pub const NFT_REG_SIZE:    usize = 16;
pub const NFT_REG32_SIZE:  usize = 4;
pub const NFT_REG32_COUNT: usize = 16;

// --- netfilter inet hooks and families the validators key on ---

pub const NF_INET_PRE_ROUTING:  u8 = 0;
pub const NF_INET_LOCAL_IN:     u8 = 1;
pub const NF_INET_FORWARD:      u8 = 2;
pub const NF_INET_LOCAL_OUT:    u8 = 3;
pub const NF_INET_POST_ROUTING: u8 = 4;
pub const NF_INET_INGRESS:      u8 = 5;

pub const NF_NETDEV_INGRESS: u8 = 0;
pub const NF_NETDEV_EGRESS:  u8 = 1;

pub const NFPROTO_UNSPEC: u8 = 0;
pub const NFPROTO_INET:   u8 = 1;
pub const NFPROTO_IPV4:   u8 = 2;
pub const NFPROTO_ARP:    u8 = 3;
pub const NFPROTO_NETDEV: u8 = 5;
pub const NFPROTO_BRIDGE: u8 = 7;
pub const NFPROTO_IPV6:   u8 = 10;
