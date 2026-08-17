// Boot-line selection of the module set.

use crate::order::Selection;

/// Modern ordered-list parameter.
pub const PARAM_LSM: &str = "lsm";
/// Legacy single-module parameter.
pub const PARAM_SECURITY: &str = "security";
/// Framework reporting parameter, a bare flag.
pub const PARAM_DEBUG: &str = "lsm.debug";

/// What the boot line said about module selection.
#[derive(Copy, Clone, Debug, Default, Eq, PartialEq)]
pub struct BootParams<'a> {
    pub lsm: Option<&'a str>,
    pub security: Option<&'a str>,
    pub debug: bool,
}

impl<'a> BootParams<'a> {
    /// Combine with the built-in order into a selection. # C: O(1)
    pub fn selection(&self, builtin: &'a str) -> Selection<'a> {
        Selection { builtin, cmdline: self.lsm, legacy: self.security }
    }
}

/// Read the framework's parameters off one boot line. # C: O(line)
///
/// A parameter given more than once takes its LAST value, which is what a
/// boot loader appending an override to an existing line produces.
pub fn parse(line: &str) -> BootParams<'_> {
    let mut out = BootParams::default();
    for token in line.split_ascii_whitespace() {
        if token == PARAM_DEBUG { out.debug = true; continue; }
        let Some((name, value)) = token.split_once('=') else { continue };
        match name {
            PARAM_LSM => out.lsm = Some(value),
            PARAM_SECURITY => out.security = Some(value),
            _ => {}
        }
    }
    out
}

#[cfg(test)]
#[path = "tests/cmdline.rs"]
mod tests;
