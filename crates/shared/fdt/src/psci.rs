//! PSCI conduit selection from the firmware node.

use alloc::vec::Vec;

use crate::{contains_string, walk, Event, Flow};

/// Firmware-selected PSCI call conduit.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum PsciConduit { Smc, Hvc }

struct Node { depth: u32, psci: bool, method: Option<PsciConduit> }

/// Read the call conduit from the first compatible PSCI node. A missing,
/// malformed, or unsupported method leaves PSCI unavailable rather than
/// guessing a trap instruction. # C: O(struct_block_size)
pub fn psci_conduit(bytes: &[u8]) -> Option<PsciConduit> {
    let mut nodes: Vec<Node> = Vec::new();
    let mut selected = None;
    let _ = walk(bytes, |event| match event {
        Event::BeginNode { depth, .. } => {
            nodes.push(Node { depth, psci: false, method: None });
            Flow::Continue
        }
        Event::Prop { name, data, depth } => {
            let Some(node) = nodes.last_mut().filter(|node| node.depth == depth) else {
                return Flow::Stop;
            };
            match name {
                b"compatible" => {
                    node.psci = contains_string(data, b"arm,psci")
                        || contains_string(data, b"arm,psci-0.2")
                        || contains_string(data, b"arm,psci-1.0");
                }
                b"method" => {
                    node.method = match data {
                        b"smc\0" => Some(PsciConduit::Smc),
                        b"hvc\0" => Some(PsciConduit::Hvc),
                        _ => None,
                    };
                }
                _ => {}
            }
            Flow::Continue
        }
        Event::EndNode { depth } => {
            let Some(node) = nodes.pop().filter(|node| node.depth == depth) else {
                return Flow::Stop;
            };
            if node.psci {
                selected = node.method;
                Flow::Stop
            } else { Flow::Continue }
        }
    });
    selected
}

#[cfg(test)]
#[path = "psci/tests.rs"]
mod tests;
