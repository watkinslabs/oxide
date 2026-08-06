use alloc::boxed::Box;
use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::ops::Deref;
use core::sync::atomic::{AtomicBool, AtomicPtr, AtomicU32, Ordering};

use crate::nft_expr::Expr;
use super::model::{ControlState, NamespaceState, NftChain, RuleCounter, StoredRule};

pub(crate) struct CompiledRule {
    pub(crate) exprs: Vec<Expr>,
    pub(crate) counter: Arc<RuleCounter>,
}

pub(crate) struct CompiledChain {
    pub(crate) table_family: u8,
    pub(crate) policy: u32,
    pub(crate) rules: Vec<CompiledRule>,
}

pub(crate) struct CompiledHook {
    pub(crate) id: u32,
    pub(crate) chains: Vec<CompiledChain>,
}

struct CompiledSet {
    table_family: u8,
    table_name: String,
    name: String,
    key_len: usize,
    keys: Vec<Vec<u8>>,
}

pub(crate) struct CompiledNamespace {
    pub(crate) hooks: Vec<CompiledHook>,
    sets: Vec<CompiledSet>,
}

impl CompiledNamespace {
    /// # C: O(log N_keys)
    pub(crate) fn set_contains(&self, set_id: usize, register: &[u8]) -> bool {
        let Some(set) = self.sets.get(set_id) else { return false; };
        let Some(key) = register.get(..set.key_len) else { return false; };
        set.keys.binary_search_by(|candidate| candidate.as_slice().cmp(key)).is_ok()
    }
}

fn compile_exprs(rule: &StoredRule, sets: &[CompiledSet]) -> Vec<Expr> {
    let mut exprs = rule.exprs.clone();
    for expr in &mut exprs {
        let Expr::Lookup { set, set_id, .. } = expr else { continue };
        *set_id = Some(sets.iter().position(|candidate| {
            candidate.table_family == rule.wire.table_family
                && candidate.table_name == rule.wire.table_name
                && candidate.name == *set
        }).expect("installed lookup retains its bound set"));
    }
    exprs
}

pub(crate) struct CompiledGeneration {
    namespaces: BTreeMap<u64, CompiledNamespace>,
}

impl CompiledGeneration {
    /// # C: O(log N_namespaces)
    pub(crate) fn namespace(&self, namespace: u64) -> Option<&CompiledNamespace> {
        self.namespaces.get(&namespace)
    }
}

/// RCU read guard for the currently published compiled generation.
pub(crate) struct GenerationGuard { ptr: *const CompiledGeneration }

impl Deref for GenerationGuard {
    type Target = CompiledGeneration;

    fn deref(&self) -> &Self::Target {
        // SAFETY: ACTIVE publications are reclaimed only after an RCU grace
        // period, and this guard holds the read-side section until Drop.
        unsafe { &*self.ptr }
    }
}

impl Drop for GenerationGuard {
    fn drop(&mut self) {
        // SAFETY: `active_generation` acquired exactly one matching read lock.
        unsafe { sched::rcu_read_unlock(); }
    }
}

static HOOK_MASK: AtomicU32 = AtomicU32::new(0);
static HOOK_OVERFLOW: AtomicBool = AtomicBool::new(false);
static ACTIVE: AtomicPtr<CompiledGeneration> = AtomicPtr::new(core::ptr::null_mut());

fn hook_bit(hook: u32) -> u32 { 1u32.checked_shl(hook).unwrap_or(0) }

fn compile_namespace(control: &mut NamespaceState) -> CompiledNamespace {
    for rule in &control.rules {
        control.counters.entry(rule.wire.handle).or_insert_with(|| Arc::new(RuleCounter::new()));
    }
    control.counters.retain(|handle, _| {
        control.rules.iter().any(|rule| rule.wire.handle == *handle)
    });

    let mut sets = Vec::with_capacity(control.sets.len());
    for set in &control.sets {
        let mut keys: Vec<Vec<u8>> = control.set_elems.iter().filter(|elem| {
            elem.table_family == set.table_family && elem.table_name == set.table_name
                && elem.set_name == set.name
        }).map(|elem| elem.key.clone()).collect();
        keys.sort();
        keys.dedup();
        sets.push(CompiledSet {
            table_family: set.table_family, table_name: set.table_name.clone(),
            name: set.name.clone(), key_len: set.key_len as usize, keys,
        });
    }

    let mut hook_ids: Vec<u32> = control.chains.iter().filter_map(|chain| chain.hook).collect();
    hook_ids.sort();
    hook_ids.dedup();
    let mut hooks = Vec::with_capacity(hook_ids.len());
    for id in hook_ids {
        let mut chains: Vec<&NftChain> = control.chains.iter()
            .filter(|chain| chain.hook == Some(id)).collect();
        chains.sort_by_key(|chain| chain.priority);
        let mut compiled_chains = Vec::with_capacity(chains.len());
        for chain in chains {
            let rules = control.rules.iter().filter(|rule| {
                rule.wire.table_family == chain.table_family
                    && rule.wire.table_name == chain.table_name
                    && rule.wire.chain_name == chain.name
            }).map(|rule| CompiledRule {
                exprs: compile_exprs(rule, &sets),
                counter: Arc::clone(control.counters.get(&rule.wire.handle)
                    .expect("counter inserted before ruleset compilation")),
            }).collect();
            compiled_chains.push(CompiledChain {
                table_family: chain.table_family, policy: chain.policy, rules,
            });
        }
        hooks.push(CompiledHook { id, chains: compiled_chains });
    }
    CompiledNamespace { hooks, sets }
}

fn compile(control: &mut ControlState) -> Box<CompiledGeneration> {
    let namespaces = control.namespaces.iter_mut().map(|(&id, state)| {
        (id, compile_namespace(state))
    }).collect();
    Box::new(CompiledGeneration { namespaces })
}

pub(super) fn publish(control: &mut ControlState) {
    let generation = compile(control);
    let mask = generation.namespaces.values().flat_map(|state| state.hooks.iter())
        .fold(0, |mask, hook| mask | hook_bit(hook.id));
    let overflow = generation.namespaces.values().flat_map(|state| state.hooks.iter())
        .any(|hook| hook_bit(hook.id) == 0);
    let new = Box::into_raw(generation);
    // The hook hint is a conservative, ever-enabled static key. Publish it
    // before the generation so an installed drop policy can never be skipped
    // by a reader observing mismatched hint/pointer epochs. Removed hooks may
    // retain one cheap RCU lookup, but never retain policy.
    HOOK_MASK.fetch_or(mask, Ordering::AcqRel);
    if overflow { HOOK_OVERFLOW.store(true, Ordering::Release); }
    let old = ACTIVE.swap(new, Ordering::AcqRel);
    if !old.is_null() {
        let old_addr = old as usize;
        sync::call_rcu(Box::new(move || {
            // SAFETY: `old` was detached from ACTIVE and a full RCU grace
            // period has elapsed, so no packet reader can retain it.
            unsafe { drop(Box::from_raw(old_addr as *mut CompiledGeneration)); }
        }));
    }
}

/// Return the current generation under an RCU read-side section. # C: O(1)
pub(crate) fn active_generation(hook: u32) -> Option<GenerationGuard> {
    let bit = hook_bit(hook);
    let active = if bit == 0 { HOOK_OVERFLOW.load(Ordering::Acquire) }
        else { HOOK_MASK.load(Ordering::Acquire) & bit != 0 };
    if !active { return None; }
    sched::rcu_read_lock();
    let ptr = ACTIVE.load(Ordering::Acquire);
    if ptr.is_null() {
        // SAFETY: pairs with the read lock immediately above.
        unsafe { sched::rcu_read_unlock(); }
        None
    } else { Some(GenerationGuard { ptr }) }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::{chain_insert, chain_remove, NftChain};
    use super::super::model::{NftRule, NftSet, StoredRule};

    #[test]
    fn hook_publication_tracks_compiled_generation() {
        let name = "hook-generation-state-test";
        let hook = crate::hook::NF_INET_PRE_ROUTING;
        let _ = chain_remove(2, name, name);
        chain_insert(NftChain {
            table_family: 2, table_name: name.into(), name: name.into(), hook: Some(hook),
            priority: 0, policy: crate::NFT_CHAIN_POLICY_ACCEPT,
        });
        let generation = active_generation(hook).expect("hook generation published");
        assert!(generation.namespace(0).unwrap().hooks.iter().any(|compiled| compiled.id == hook));
        drop(generation);
        assert_eq!(chain_remove(2, name, name), 1);
        let generation = active_generation(hook).expect("enabled hook hint remains conservative");
        assert!(!generation.namespace(0).unwrap().hooks.iter().any(|compiled| compiled.id == hook));
    }

    #[test]
    fn lookup_compilation_binds_the_exact_set_index() {
        let mut control = NamespaceState::new();
        control.sets.push(NftSet {
            table_family: 2, table_name: "table".into(), name: "other".into(),
            key_type: 0, key_len: 4, data_type: 0, data_len: 0, flags: 0,
        });
        control.sets.push(NftSet {
            table_family: 2, table_name: "table".into(), name: "bound".into(),
            key_type: 0, key_len: 4, data_type: 0, data_len: 0, flags: 0,
        });
        control.set_elems.push(super::super::model::NftSetElem {
            table_family: 2, table_name: "table".into(), set_name: "bound".into(),
            key: alloc::vec![10, 0, 0, 5], data: Vec::new(),
        });
        control.chains.push(NftChain {
            table_family: 2, table_name: "table".into(), name: "input".into(),
            hook: Some(1), priority: 0, policy: crate::NFT_CHAIN_POLICY_ACCEPT,
        });
        control.rules.push(StoredRule {
            wire: NftRule {
                table_family: 2, table_name: "table".into(), chain_name: "input".into(),
                handle: 1, raw_expr: Vec::new(),
            },
            exprs: alloc::vec![Expr::Lookup {
                sreg: 1, set: "bound".into(), set_id: None, invert: false,
            }],
        });

        let compiled = compile_namespace(&mut control);
        assert!(matches!(compiled.hooks[0].chains[0].rules[0].exprs[0],
            Expr::Lookup { set_id: Some(1), .. }));
        assert!(compiled.set_contains(1, &[10, 0, 0, 5]));
        assert!(!compiled.set_contains(0, &[10, 0, 0, 5]));
    }
}
