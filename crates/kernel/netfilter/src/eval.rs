use crate::{NFT_CHAIN_POLICY_DROP, active_generation, nft_expr};

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

/// Evaluate the immutable ruleset generation published for `hook_id`.
/// # C: O(N_chains × N_rules × N_exprs)
pub fn eval(hook_id: u32, pkt: &[u8], family: u8) -> Verdict {
    eval_in(0, hook_id, pkt, family)
}

/// Evaluate one network namespace's immutable ruleset generation.
/// # C: O(log N_namespaces + N_chains × N_rules × N_exprs)
pub fn eval_in(namespace: u64, hook_id: u32, pkt: &[u8], family: u8) -> Verdict {
    let Some(generation) = active_generation(hook_id) else { return Verdict::Accept; };
    let Some(state) = generation.namespace(namespace) else { return Verdict::Accept; };
    let Some(hook) = state.hooks.iter().find(|hook| hook.id == hook_id) else {
        return Verdict::Accept;
    };
    for chain in hook.chains.iter().filter(|chain| chain.table_family == family) {
        let mut chain_verdict = None;
        for rule in &chain.rules {
            let lookup = |set_id: Option<usize>, _set_name: &str, register: &[u8]| {
                state.set_contains(set_id.expect("compiled lookup has a set id"), register)
            };
            let mut packets = 0u64;
            let mut bytes = 0u64;
            let verdict = nft_expr::run_rule_full(
                &rule.exprs,
                pkt,
                Some(&lookup),
                family,
                &mut packets,
                &mut bytes,
            );
            if packets != 0 { rule.counter.bump(packets, bytes); }
            match verdict {
                Some(nft_expr::NF_DROP) => { chain_verdict = Some(Verdict::Drop); break; }
                Some(nft_expr::NF_ACCEPT) => { chain_verdict = Some(Verdict::Accept); break; }
                _ => {}
            }
        }
        let verdict = chain_verdict.unwrap_or_else(|| match chain.policy {
            NFT_CHAIN_POLICY_DROP => Verdict::Drop,
            _ => Verdict::Accept,
        });
        if verdict == Verdict::Drop { return Verdict::Drop; }
    }
    Verdict::Accept
}
