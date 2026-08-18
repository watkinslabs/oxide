//! Firmware CPU descriptions → validated performance domains.

use alloc::vec::Vec;

use super::decode::{Coordination, PctRegister, Psd, Pstate, frequency_at};

/// Complete performance description belonging to one logical CPU.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CpuDescription {
    pub cpu: usize,
    pub states: Vec<Pstate>,
    pub control: PctRegister,
    pub status: PctRegister,
    pub platform_limit: Option<u32>,
    pub psd: Option<Psd>,
}

/// One policy the generic scaling core may publish.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PolicyDomain {
    pub cpus: Vec<usize>,
    pub states: Vec<Pstate>,
    pub control: PctRegister,
    pub coordination: Coordination,
    pub platform_max_khz: u32,
}

/// Whether this firmware coordination mode can switch from the scheduler.
/// A software-any domain is changed on the policy CPU and firmware guarantees
/// that write affects the whole domain. # C: O(1)
pub fn fast_switch_admitted(coordination: Coordination) -> bool {
    matches!(coordination, Coordination::SoftwareAny)
}

/// Form domains from the processor dependencies firmware declared. A `_PSD`
/// domain is admitted only when every processor it names supplied identical
/// state/control descriptions; otherwise publishing a partial shared policy
/// would program one CPU while claiming to govern all of them. # C: O(N²)
pub fn domains(mut descriptions: Vec<CpuDescription>) -> Vec<PolicyDomain> {
    let mut out = Vec::new();
    while let Some(first) = descriptions.pop() {
        let key = first.psd.map(|psd| psd.domain);
        let mut group = alloc::vec![first];
        let mut index = 0usize;
        while index < descriptions.len() {
            if key.is_some_and(|domain| descriptions[index].psd.map(|psd| psd.domain) == Some(domain)) {
                group.push(descriptions.swap_remove(index));
            } else {
                index += 1;
            }
        }
        if let Some(domain) = build_domain(&group) { out.push(domain); }
    }
    out
}

/// Build one policy after all of its CPU descriptions have been collected.
/// # C: O(cpus × states)
fn build_domain(group: &[CpuDescription]) -> Option<PolicyDomain> {
    let first = group.first()?;
    if let Some(psd) = first.psd {
        if usize::try_from(psd.processors).ok()? != group.len() { return None; }
    }
    if group.iter().any(|description| description.states != first.states
        || description.control != first.control || description.status != first.status
        || description.psd.map(|psd| psd.coordination) != first.psd.map(|psd| psd.coordination)) {
        return None;
    }
    let mut cpus: Vec<usize> = group.iter().map(|description| description.cpu).collect();
    cpus.sort_unstable();
    if cpus.windows(2).any(|pair| pair[0] == pair[1]) { return None; }
    let mut platform_max_khz = first.states.first()?.frequency_khz;
    for description in group {
        let max = match description.platform_limit {
            Some(index) => frequency_at(&description.states, index)?,
            None => first.states.first()?.frequency_khz,
        };
        platform_max_khz = platform_max_khz.min(max);
    }
    Some(PolicyDomain {
        cpus, states: first.states.clone(), control: first.control,
        coordination: first.psd.map(|psd| psd.coordination).unwrap_or(Coordination::SoftwareAny),
        platform_max_khz,
    })
}

#[cfg(test)]
#[path = "policy_tests.rs"]
mod tests;
