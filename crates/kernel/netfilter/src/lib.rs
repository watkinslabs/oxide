#![no_std]

extern crate alloc;

// Module manifest:
// - `protocol`: nfnetlink/nftables wire structs, subsystem ids, and UAPI attrs.
// - `state`: in-memory tables/chains/rules/sets/objects plus mutation helpers.
// - `eval`: hook evaluation over the stored ruleset.
// - `nl`: shared netlink attr encoding/decoding and top-level NFNL dispatch.
mod eval;
mod nl;
mod nft_dispatch;
mod nft_dispatch_helpers;
pub mod nft_expr;
mod protocol;
mod state;

pub use eval::{Verdict, eval};
pub use nl::handle;
pub use protocol::{
    Nfgenmsg, NFT_CHAIN_POLICY_ACCEPT, NFT_CHAIN_POLICY_DROP, hook, nft_msg, nfta_chain,
    nfta_gen, nfta_obj, nfta_rule, nfta_set, nfta_set_elem, nfta_table, subsys,
};
pub use state::{
    NftChain, NftObject, NftRule, NftSet, NftSetElem, NftTable, chain_insert, chain_remove,
    chains_snapshot, counter_bump, counter_get, gen_bump, gen_current, next_rule_handle,
    object_insert, object_remove, objects_snapshot, rule_insert, rule_remove, rules_snapshot,
    set_elem_insert, set_elem_lookup, set_elem_remove, set_elems_snapshot, set_insert,
    set_remove, sets_snapshot, table_insert, table_remove, tables_snapshot,
};

pub(crate) use nl::{
    build_newchain_reply, build_newrule_reply, build_newset_reply, build_newtable_reply,
    find_bytes_attr, find_str_attr, find_u32_attr, find_u64_attr, nlmsg_ack, put_nlattr,
    put_nlattr_str, put_nlattr_u32,
};
pub(crate) use state::{CHAINS, OBJECTS, RULES, SETS, TABLES};

#[cfg(test)]
mod tests;
