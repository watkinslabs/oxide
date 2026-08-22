use crate::{NFT_CHAIN_POLICY_DROP, active_generation, nft_expr};
use crate::nft_expr::{EvalCtx, uapi};

/// Netfilter verdict.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum Verdict {
    Drop,
    Accept,
    Stolen,
    Queue(u16),
    Repeat,
    Stop,
}

/// A hook verdict and the packet mark left by its ruleset.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct EvalResult {
    pub verdict: Verdict,
    pub mark: u32,
}

impl Verdict {
    /// # C: O(1)
    pub fn as_u32(self) -> u32 {
        match self {
            Verdict::Drop => uapi::NF_DROP as u32,
            Verdict::Accept => uapi::NF_ACCEPT as u32,
            Verdict::Stolen => uapi::NF_STOLEN as u32,
            Verdict::Queue(q) => uapi::nf_queue_nr(q) as u32,
            Verdict::Repeat => uapi::NF_REPEAT as u32,
            Verdict::Stop => uapi::NF_STOP as u32,
        }
    }

    /// Verdict a rule's absolute code names. # C: O(1)
    pub fn from_code(code: i32) -> Option<Self> {
        Some(match code & uapi::NF_VERDICT_MASK {
            uapi::NF_DROP => Verdict::Drop,
            uapi::NF_ACCEPT => Verdict::Accept,
            uapi::NF_STOLEN => Verdict::Stolen,
            uapi::NF_QUEUE => Verdict::Queue(uapi::nf_verdict_qnum(code)),
            uapi::NF_REPEAT => Verdict::Repeat,
            uapi::NF_STOP => Verdict::Stop,
            _ => return None,
        })
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
    eval_in_with_mark(namespace, hook_id, pkt, family, 0).verdict
}

/// Evaluate one hook while retaining nft's mutable packet mark. # C: O(N rules)
pub fn eval_in_with_mark(namespace: u64, hook_id: u32, pkt: &[u8], family: u8,
                         mark: u32) -> EvalResult {
    let input = crate::eval_context::Input::bare(namespace, hook_id, pkt, family, mark);
    eval_context(&input)
}

/// Evaluate one hook from the live packet-buffer and hook ownership. # C: O(N rules)
pub fn eval_hook(input: &net::stack::NfHookCtx<'_>) -> EvalResult {
    let input = crate::eval_context::Input::from_hook(input);
    eval_context(&input)
}

fn eval_context(input: &crate::eval_context::Input<'_>) -> EvalResult {
    let namespace = input.namespace;
    let hook_id = input.hook_id;
    let pkt = input.pkt;
    let family = input.family;
    let mut mark = input.mark;
    let Some(generation) = active_generation(hook_id) else {
        return EvalResult { verdict: Verdict::Accept, mark };
    };
    let Some(state) = generation.namespace(namespace) else {
        return EvalResult { verdict: Verdict::Accept, mark };
    };
    let Some(hook) = state.hooks.iter().find(|hook| hook.id == hook_id) else {
        return EvalResult { verdict: Verdict::Accept, mark };
    };
    for chain in hook.chains.iter().filter(|chain| chain.table_family == family) {
        let mut chain_verdict = None;
        for rule in &chain.rules {
            let lookup = |set_id: Option<usize>, _set_name: &str, register: &[u8]| {
                state.set_contains(set_id.expect("compiled lookup has a set id"), register)
            };
            let mut ctx = EvalCtx::new(pkt, family, &rule.states);
            input.populate(&mut ctx, mark);
            ctx.set_lookup = Some(&lookup);
            let verdict = nft_expr::run_rule_ctx(&rule.exprs, &mut ctx);
            mark = ctx.mark;
            if ctx.packets != 0 { rule.counter.bump(ctx.packets, ctx.bytes); }
            if let Some(decided) = Verdict::from_code(verdict.code) {
                chain_verdict = Some(decided);
                break;
            }
        }
        let verdict = chain_verdict.unwrap_or_else(|| match chain.policy {
            NFT_CHAIN_POLICY_DROP => Verdict::Drop,
            _ => Verdict::Accept,
        });
        if verdict != Verdict::Accept { return EvalResult { verdict, mark }; }
    }
    EvalResult { verdict: Verdict::Accept, mark }
}
