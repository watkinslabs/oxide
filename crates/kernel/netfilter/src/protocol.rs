/// 4-byte `struct nfgenmsg` per `linux/netfilter/nfnetlink.h`.
#[repr(C)]
#[derive(Copy, Clone, Debug, Default)]
pub struct Nfgenmsg {
    pub nfgen_family: u8,
    pub version:      u8,
    pub res_id:       u16,
}

impl Nfgenmsg {
    pub const SIZE: usize = 4;

    /// # C: O(1)
    pub fn parse(buf: &[u8]) -> Option<Self> {
        if buf.len() < Self::SIZE { return None; }
        Some(Self {
            nfgen_family: buf[0],
            version:      buf[1],
            res_id:       u16::from_be_bytes([buf[2], buf[3]]),
        })
    }

    /// # C: O(1)
    pub fn write_to(&self, buf: &mut [u8]) {
        buf[0] = self.nfgen_family;
        buf[1] = self.version;
        buf[2..4].copy_from_slice(&self.res_id.to_be_bytes());
    }
}

/// NFNL subsystem ids per Linux.
pub mod subsys {
    pub const NFNL_SUBSYS_NONE:              u8 = 0;
    pub const NFNL_SUBSYS_CTNETLINK:         u8 = 1;
    pub const NFNL_SUBSYS_QUEUE:             u8 = 3;
    pub const NFNL_SUBSYS_ULOG:              u8 = 4;
    pub const NFNL_SUBSYS_OSF:               u8 = 5;
    pub const NFNL_SUBSYS_IPSET:             u8 = 6;
    pub const NFNL_SUBSYS_ACCT:              u8 = 7;
    pub const NFNL_SUBSYS_CTNETLINK_TIMEOUT: u8 = 8;
    pub const NFNL_SUBSYS_CTHELPER:          u8 = 9;
    pub const NFNL_SUBSYS_NFTABLES:          u8 = 10;
    pub const NFNL_SUBSYS_NFT_COMPAT:        u8 = 11;
    pub const NFNL_SUBSYS_HOOK:              u8 = 12;
}

/// nf_tables command ids per Linux `nf_tables.h::nft_msg_types`.
pub mod nft_msg {
    pub const NFT_MSG_NEWTABLE:   u8 = 0;
    pub const NFT_MSG_GETTABLE:   u8 = 1;
    pub const NFT_MSG_DELTABLE:   u8 = 2;
    pub const NFT_MSG_NEWCHAIN:   u8 = 3;
    pub const NFT_MSG_GETCHAIN:   u8 = 4;
    pub const NFT_MSG_DELCHAIN:   u8 = 5;
    pub const NFT_MSG_NEWRULE:    u8 = 6;
    pub const NFT_MSG_GETRULE:    u8 = 7;
    pub const NFT_MSG_DELRULE:    u8 = 8;
    pub const NFT_MSG_NEWSET:     u8 = 9;
    pub const NFT_MSG_GETSET:     u8 = 10;
    pub const NFT_MSG_DELSET:     u8 = 11;
    pub const NFT_MSG_NEWSETELEM: u8 = 12;
    pub const NFT_MSG_GETSETELEM: u8 = 13;
    pub const NFT_MSG_DELSETELEM: u8 = 14;
    pub const NFT_MSG_NEWGEN:     u8 = 15;
    pub const NFT_MSG_GETGEN:     u8 = 16;
    pub const NFT_MSG_NEWOBJ:     u8 = 18;
    pub const NFT_MSG_GETOBJ:     u8 = 19;
    pub const NFT_MSG_DELOBJ:     u8 = 20;
}

pub mod nfta_obj {
    pub const NFTA_OBJ_TABLE:  u16 = 1;
    pub const NFTA_OBJ_NAME:   u16 = 2;
    pub const NFTA_OBJ_TYPE:   u16 = 3;
    pub const NFTA_OBJ_DATA:   u16 = 4;
    pub const NFTA_OBJ_USE:    u16 = 5;
    pub const NFTA_OBJ_HANDLE: u16 = 6;
}

pub mod nfta_gen {
    pub const NFTA_GEN_ID:        u16 = 1;
    pub const NFTA_GEN_PROC_PID:  u16 = 2;
    pub const NFTA_GEN_PROC_NAME: u16 = 3;
}

pub mod nfta_table {
    pub const NFTA_TABLE_NAME:  u16 = 1;
    pub const NFTA_TABLE_FLAGS: u16 = 2;
    pub const NFTA_TABLE_USE:   u16 = 3;
}

pub mod nfta_set {
    pub const NFTA_SET_TABLE:     u16 = 1;
    pub const NFTA_SET_NAME:      u16 = 2;
    pub const NFTA_SET_FLAGS:     u16 = 3;
    pub const NFTA_SET_KEY_TYPE:  u16 = 4;
    pub const NFTA_SET_KEY_LEN:   u16 = 5;
    pub const NFTA_SET_DATA_TYPE: u16 = 6;
    pub const NFTA_SET_DATA_LEN:  u16 = 7;
    pub const NFTA_SET_POLICY:    u16 = 8;
    pub const NFTA_SET_DESC:      u16 = 9;
    pub const NFTA_SET_ID:        u16 = 10;
    pub const NFTA_SET_TIMEOUT:   u16 = 11;
    pub const NFTA_SET_USERDATA:  u16 = 13;
}

pub mod nfta_set_elem {
    pub const NFTA_SET_ELEM_LIST_TABLE:    u16 = 1;
    pub const NFTA_SET_ELEM_LIST_SET:      u16 = 2;
    pub const NFTA_SET_ELEM_LIST_ELEMENTS: u16 = 3;
    pub const NFTA_SET_ELEM_KEY:           u16 = 1;
    pub const NFTA_SET_ELEM_DATA:          u16 = 2;
    pub const NFTA_SET_ELEM_FLAGS:         u16 = 3;
    pub const NFTA_DATA_VALUE:             u16 = 1;
}

pub mod nfta_rule {
    pub const NFTA_RULE_TABLE:       u16 = 1;
    pub const NFTA_RULE_CHAIN:       u16 = 2;
    pub const NFTA_RULE_HANDLE:      u16 = 3;
    pub const NFTA_RULE_EXPRESSIONS: u16 = 4;
    pub const NFTA_RULE_COMPAT:      u16 = 5;
    pub const NFTA_RULE_POSITION:    u16 = 6;
    pub const NFTA_RULE_USERDATA:    u16 = 7;
    pub const NFTA_RULE_ID:          u16 = 9;
}

pub mod nfta_chain {
    pub const NFTA_CHAIN_TABLE:    u16 = 1;
    pub const NFTA_CHAIN_HANDLE:   u16 = 2;
    pub const NFTA_CHAIN_NAME:     u16 = 3;
    pub const NFTA_CHAIN_HOOK:     u16 = 4;
    pub const NFTA_CHAIN_POLICY:   u16 = 5;
    pub const NFTA_CHAIN_USE:      u16 = 6;
    pub const NFTA_CHAIN_TYPE:     u16 = 7;
    pub const NFTA_CHAIN_COUNTERS: u16 = 8;
    pub const NFTA_CHAIN_FLAGS:    u16 = 9;
    pub const NFTA_CHAIN_ID:       u16 = 11;
}

pub mod hook {
    pub const NF_INET_PRE_ROUTING:  u32 = 0;
    pub const NF_INET_LOCAL_IN:     u32 = 1;
    pub const NF_INET_FORWARD:      u32 = 2;
    pub const NF_INET_LOCAL_OUT:    u32 = 3;
    pub const NF_INET_POST_ROUTING: u32 = 4;
    pub const NF_INET_NUM_HOOKS:    u32 = 5;
}

pub const NFT_CHAIN_POLICY_ACCEPT: u32 = 1;
pub const NFT_CHAIN_POLICY_DROP:   u32 = 0;
