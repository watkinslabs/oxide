// Module manifest:
// - `model`: nftables control records and lock/counter primitives.
// - `generation`: immutable compiled packet-path state and RCU publication.
// - `store`: canonical control-plane mutations and nfnetlink transactions.
mod generation;
mod model;
mod store;

pub use model::{NftChain, NftObject, NftRule, NftSet, NftSetElem, NftTable};
pub use store::{
    chain_insert, chain_insert_in, chain_remove, chain_remove_in, chains_snapshot,
    chains_snapshot_in, counter_get, counter_get_in, gen_current, gen_current_in, next_rule_handle,
    object_insert, object_insert_in, object_remove, object_remove_in, objects_snapshot,
    objects_snapshot_in, rule_insert, rule_insert_in, rule_remove, rule_remove_in, rules_snapshot,
    rules_snapshot_in, set_elem_insert, set_elem_insert_in, set_elem_lookup, set_elem_lookup_in,
    set_elem_remove, set_elem_remove_in, set_elems_snapshot, set_elems_snapshot_in, set_insert,
    set_insert_in, set_remove, set_remove_in, sets_snapshot, sets_snapshot_in, table_insert,
    table_insert_in, table_remove, table_remove_in, tables_snapshot, tables_snapshot_in,
    SetRemoveError,
};

pub(crate) use generation::active_generation;
pub(crate) use store::{
    batch_abort, batch_begin, batch_commit, nfnl_lock, rules_remove_in, set_elems_insert_in,
    set_elems_remove_in,
};
