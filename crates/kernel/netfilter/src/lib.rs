#![no_std]

extern crate alloc;
#[cfg(test)]
extern crate std;

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

pub use eval::{EvalResult, Verdict, eval, eval_in, eval_in_with_mark};
pub use nl::handle;
pub use protocol::{
    Nfgenmsg, NFT_CHAIN_POLICY_ACCEPT, NFT_CHAIN_POLICY_DROP, hook, nft_msg, nfta_chain,
    nfta_gen, nfta_obj, nfta_rule, nfta_set, nfta_set_elem, nfta_table, subsys,
};
pub use state::{
    NftChain, NftObject, NftRule, NftSet, NftSetElem, NftTable, chain_insert, chain_insert_in,
    chain_remove, chain_remove_in, chains_snapshot, chains_snapshot_in, counter_get,
    counter_get_in, gen_current, gen_current_in, next_rule_handle, object_insert,
    object_insert_in, object_remove, object_remove_in, objects_snapshot, objects_snapshot_in,
    rule_insert, rule_insert_in, rule_remove, rule_remove_in, rules_snapshot, rules_snapshot_in,
    set_elem_insert, set_elem_insert_in, set_elem_lookup, set_elem_lookup_in, set_elem_remove,
    set_elem_remove_in, set_elems_snapshot, set_elems_snapshot_in, set_insert, set_insert_in,
    set_remove, set_remove_in, sets_snapshot, sets_snapshot_in, table_insert, table_insert_in,
    table_remove, table_remove_in, tables_snapshot, tables_snapshot_in, SetRemoveError,
};

pub(crate) use nl::{
    build_newchain_reply, build_newrule_reply, build_newset_reply, build_newtable_reply,
    find_bytes_attr, find_str_attr, find_u32_attr, find_u64_attr, nlmsg_ack, put_nlattr,
    put_nlattr_str, put_nlattr_u32,
};
pub(crate) use state::{
    active_generation, batch_abort, batch_begin, batch_commit, nfnl_lock, rules_remove_in,
    set_elems_insert_in, set_elems_remove_in,
};

#[cfg(test)]
mod tests;
