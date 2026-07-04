use alloc::vec::Vec;

use crate::{
    CHAINS, NFT_CHAIN_POLICY_DROP, NftChain, RULES, counter_bump, nft_expr, set_elem_lookup,
    sets_snapshot,
};

/// Netfilter verdict per `linux/netfilter.h`.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum Verdict {
    Drop,
    Accept,
    Stolen,
    Queue(u16),
    Repeat,
}

impl Verdict {
    /// # C: O(1)
    pub fn as_u32(self) -> u32 {
        match self {
            Verdict::Drop => 0,
            Verdict::Accept => 1,
            Verdict::Stolen => 2,
            Verdict::Queue(q) => 3 | ((q as u32) << 16),
            Verdict::Repeat => 4,
        }
    }
}

/// # C: O(N_chains × N_rules × expr_len)
pub fn eval(hook_id: u32, pkt: &[u8], family: u8) -> Verdict {
    let mut chains: Vec<NftChain> = CHAINS.lock().clone();
    chains.retain(|c| c.hook == Some(hook_id));
    chains.sort_by_key(|c| c.priority);
    let rules_snap = RULES.lock().clone();
    for c in chains.iter() {
        let mut chain_verdict: Option<Verdict> = None;
        for r in rules_snap.iter().filter(|r| {
            r.table_family == c.table_family && r.table_name == c.table_name && r.chain_name == c.name
        }) {
            let exprs = nft_expr::parse_exprs(&r.raw_expr);
            let rule_family = r.table_family;
            let table = r.table_name.clone();
            let sets = sets_snapshot();
            let lookup = move |set_name: &str, regbytes: &[u8]| -> Option<Vec<u8>> {
                let s = sets.iter().find(|s| {
                    s.table_family == rule_family
                        && s.table_name.as_str() == table.as_str()
                        && s.name == set_name
                })?;
                let key = regbytes.get(..s.key_len as usize)?;
                set_elem_lookup(rule_family, &table, set_name, key)
            };
            let mut pkts = 0u64;
            let mut bytes = 0u64;
            let verdict = nft_expr::run_rule_full(&exprs, pkt, Some(&lookup), family, &mut pkts, &mut bytes);
            if pkts != 0 { counter_bump(r.handle, pkts, bytes); }
            match verdict {
                Some(nft_expr::NF_DROP) => { chain_verdict = Some(Verdict::Drop); break; }
                Some(nft_expr::NF_ACCEPT) => { chain_verdict = Some(Verdict::Accept); break; }
                _ => {}
            }
        }
        let v = chain_verdict.unwrap_or_else(|| match c.policy {
            NFT_CHAIN_POLICY_DROP => Verdict::Drop,
            _ => Verdict::Accept,
        });
        if v == Verdict::Drop { return Verdict::Drop; }
    }
    Verdict::Accept
}
