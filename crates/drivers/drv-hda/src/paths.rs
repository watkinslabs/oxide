// Path search through the widget graph. A route runs from a converter to a
// pin (or a pin to a converter); the search prefers a direct connection over
// any longer route and never traverses another converter or pin on the way.

use alloc::vec::Vec;

use crate::graph::Codec;
use crate::widget::WidgetType;

/// Longest route the search will build.
pub const MAX_PATH_DEPTH: usize = 10;

/// One node on a route, with the connection index its predecessor occupies
/// in this node's list.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct Hop {
    pub nid: u8,
    /// Connection index selecting the previous hop; `None` at the source.
    pub sel: Option<u8>,
    /// This node is a selector, so the index has to be written to it.
    pub multi: bool,
}

/// A complete route, source first.
#[derive(Clone, Debug, Eq, PartialEq, Default)]
pub struct NidPath {
    pub hops: Vec<Hop>,
}

impl NidPath {
    /// # C: O(1)
    pub fn source(&self) -> Option<u8> { self.hops.first().map(|hop| hop.nid) }
    /// # C: O(1)
    pub fn sink(&self) -> Option<u8> { self.hops.last().map(|hop| hop.nid) }
    /// # C: O(1)
    pub fn len(&self) -> usize { self.hops.len() }
    /// # C: O(1)
    pub fn is_empty(&self) -> bool { self.hops.is_empty() }
    /// Nodes from the sink back towards the source — the order the control
    /// search walks, because the widget nearest the jack owns the control.
    /// # C: O(1)
    pub fn from_sink(&self) -> impl Iterator<Item = u8> + '_ {
        self.hops.iter().rev().map(|hop| hop.nid)
    }
    /// # C: O(1)
    pub fn contains(&self, nid: u8) -> bool { self.hops.iter().any(|hop| hop.nid == nid) }
}

/// What the search is looking for at the far end.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum Source {
    /// This exact widget.
    Nid(u8),
    /// Any analog audio-output widget not already claimed.
    UnusedDac,
    /// Any analog audio-input widget not already claimed.
    UnusedAdc,
}

fn terminal(kind: Option<WidgetType>) -> bool {
    matches!(kind, Some(WidgetType::AudioOut) | Some(WidgetType::AudioIn) | Some(WidgetType::Pin))
}

fn matches_source(codec: &Codec, candidate: u8, source: Source, used: &[u8]) -> bool {
    match source {
        Source::Nid(nid) => candidate == nid,
        Source::UnusedDac => codec.widget(candidate).is_some_and(|w| w.is_dac() && !w.digital())
            && !used.contains(&candidate),
        Source::UnusedAdc => codec.widget(candidate).is_some_and(|w| w.is_adc() && !w.digital())
            && !used.contains(&candidate),
    }
}

fn dfs(codec: &Codec, source: Source, to: u8, used: &[u8], depth: usize, hops: &mut Vec<Hop>) -> bool {
    let Some(node) = codec.widget(to) else { return false; };
    let multi = node.conns.len() > 1 && node.kind() != WidgetType::AudioMixer;

    // A direct connection always wins over a longer route through the same
    // fan-in, so the whole list is checked before any recursion.
    for (index, &candidate) in node.conns.iter().enumerate() {
        if matches_source(codec, candidate, source, used) {
            hops.push(Hop { nid: candidate, sel: None, multi: false });
            hops.push(Hop { nid: to, sel: Some(index as u8), multi });
            return true;
        }
    }
    if depth + 1 >= MAX_PATH_DEPTH { return false; }
    for (index, &candidate) in node.conns.iter().enumerate() {
        if terminal(codec.kind_of(candidate)) { continue; }
        if dfs(codec, source, candidate, used, depth + 1, hops) {
            hops.push(Hop { nid: to, sel: Some(index as u8), multi });
            return true;
        }
    }
    false
}

/// Build a route ending at `to`. # C: O(widgets × fan-in, bounded by depth)
pub fn find(codec: &Codec, source: Source, to: u8, used: &[u8]) -> Option<NidPath> {
    if let Source::Nid(nid) = source {
        if nid == to { return Some(NidPath { hops: alloc::vec![Hop { nid, sel: None, multi: false }] }); }
    }
    let mut hops = Vec::new();
    if dfs(codec, source, to, used, 0, &mut hops) { Some(NidPath { hops }) } else { None }
}

/// Does any route run from `from` to `to`? # C: as [`find`]
pub fn reachable(codec: &Codec, from: u8, to: u8) -> bool {
    find(codec, Source::Nid(from), to, &[]).is_some()
}

/// Widget on the route that owns the volume control: the one nearest the
/// jack with an output amplifier that has more than one step.
/// # C: O(path length)
pub fn volume_nid(codec: &Codec, path: &NidPath) -> Option<u8> {
    path.from_sink().find(|&nid| {
        codec.widget(nid)
            .and_then(|w| w.out_amp(codec.fg_amp_out))
            .is_some_and(|caps| crate::widget::amp_caps(caps).num_steps != 0)
    })
}

/// Widget on the route that owns the mute. An interior node may mute on its
/// input side; the endpoints may only mute on their output side.
/// # C: O(path length)
pub fn mute_nid(codec: &Codec, path: &NidPath) -> Option<(u8, bool)> {
    let last = path.len().saturating_sub(1);
    for (offset, hop) in path.hops.iter().enumerate().rev() {
        let Some(w) = codec.widget(hop.nid) else { continue; };
        if w.out_amp(codec.fg_amp_out).is_some_and(|caps| crate::widget::amp_caps(caps).mute) {
            return Some((hop.nid, true));
        }
        if offset != last && offset != 0
            && w.in_amp(codec.fg_amp_in).is_some_and(|caps| crate::widget::amp_caps(caps).mute) {
            return Some((hop.nid, false));
        }
    }
    None
}

#[cfg(test)]
#[path = "tests/paths.rs"]
mod tests;
