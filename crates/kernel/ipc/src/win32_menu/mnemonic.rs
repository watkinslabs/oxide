//! The prefix rules a menu label is drawn under.
//!
//! A menu item's stored text carries its keyboard mnemonic inline: the prefix
//! character is consumed and the character behind it is underlined, a doubled
//! prefix stands for one literal prefix character, and a prefix that is the
//! last character of the label has nothing to mark, so it is drawn as itself.
//! Only the first mnemonic of a label is marked. Every consumer of a label
//! goes through here, so what is measured, what is drawn and which key
//! selects the item can never disagree.
use alloc::vec::Vec;

/// Mnemonic prefix of a label.
pub const MNEMONIC_PREFIX: u16 = b'&' as u16;
/// Legacy alphabet prefix, marking a mnemonic exactly as the ampersand does.
pub const ALPHA_PREFIX: u16 = 30;
/// Legacy katakana prefix: the prefix and the access key behind it are both
/// dropped from the drawn label and neither is marked.
pub const KANA_PREFIX: u16 = 31;
/// A label splits here into the item name and the accelerator behind it: the
/// half behind a tab is drawn from the menu's tab column rightwards, the half
/// behind a flush-right unit ends at that column.
pub const TAB_SPLIT: u16 = 9;
pub const FLUSH_SPLIT: u16 = 8;

/// One label as it is drawn: the units left after the prefix rules, and the
/// index into those units of the character the underline sits under.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct DisplayText { pub units: Vec<u16>, pub mnemonic: Option<usize> }

/// Units of a label up to its terminator. # C: O(len)
pub fn stored_len(text: &[u16]) -> usize { text.iter().position(|unit| *unit == 0).unwrap_or(text.len()) }

/// Resolve one label into what is drawn for it. # C: O(len)
pub fn display_text(text: &[u16]) -> DisplayText {
    let end = stored_len(text);
    let mut out = DisplayText { units: Vec::new(), mnemonic: None };
    if out.units.try_reserve(end).is_err() { return out; }
    let mut index = 0;
    while index < end {
        let unit = text[index];
        // A prefix with nothing behind it inside the label marks nothing and
        // stands for itself.
        if index + 1 >= end { out.units.push(unit); break; }
        match unit {
            MNEMONIC_PREFIX | ALPHA_PREFIX => {
                index += 1;
                if text[index] == MNEMONIC_PREFIX { out.units.push(MNEMONIC_PREFIX); index += 1; continue; }
                if out.mnemonic.is_none() { out.mnemonic = Some(out.units.len()); }
            }
            KANA_PREFIX => { index += 2; continue; }
            _ => { out.units.push(unit); index += 1; }
        }
    }
    out
}

/// Where the second half of a split label sits against the tab column.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum AccelAlign { Tab, FlushRight }

/// One label as the runs it draws as: the item name, and the accelerator half
/// behind the split unit when the label carries one. The split is looked for
/// in the stored units, ahead of the prefix rules, so a prefix cannot hide it
/// and each half carries its own mnemonic.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct LabelHalves { pub name: DisplayText, pub accel: Option<(AccelAlign, DisplayText)> }

/// Split one label at its first tab or flush-right unit and resolve each half.
/// # C: O(len)
pub fn label_halves(text: &[u16]) -> LabelHalves {
    let end = stored_len(text);
    let split = text[..end].iter().position(|unit| *unit == TAB_SPLIT || *unit == FLUSH_SPLIT);
    let Some(index) = split else { return LabelHalves { name: display_text(&text[..end]), accel: None }; };
    let align = if text[index] == TAB_SPLIT { AccelAlign::Tab } else { AccelAlign::FlushRight };
    LabelHalves { name: display_text(&text[..index]), accel: Some((align, display_text(&text[index + 1..end]))) }
}

/// Width of one label in characters, as it is drawn. # C: O(len)
pub fn display_len(text: &[u16]) -> usize { display_text(text).units.len() }

/// The character one label's mnemonic selects, if it marks one. # C: O(len)
pub fn mnemonic_char(text: &[u16]) -> Option<u16> {
    let drawn = label_halves(text).name;
    drawn.mnemonic.and_then(|index| drawn.units.get(index).copied())
}

#[cfg(test)]
#[path = "tests/mnemonic.rs"]
mod tests;
