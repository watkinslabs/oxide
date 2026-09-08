//! The locale and UI-language a process reports and can replace.
//!
//! Each process carries its own three values: the system locale, the user
//! locale, and the user interface language. The install language is not
//! separately settable - it is the language half of the system locale - so it
//! is derived here rather than stored.

/// Language identifier half of a locale identifier.
/// # C: O(1)
pub fn language_of(lcid: u32) -> u16 { lcid as u16 }

/// An output the service cannot write is an access violation, which is what
/// a caller that passed no output sees on the same call.
const STATUS_ACCESS_VIOLATION: u64 = 0xc000_0005;

/// Which of a process's two locales one call names.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum Which { System, User }

/// The three values one process reports, and the rules for replacing them.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct Locales { pub system: u32, pub user: u32, pub ui: u16 }

impl Locales {
    /// Read the three stored values, where an unset one is zero: the system
    /// locale falls back to the baseline, the user locale to the system one,
    /// and the interface language to the user locale's language half.
    /// # C: O(1)
    pub fn from_stored(system: u32, user: u32, ui: u16) -> Self {
        let system = if system == 0 { crate::nt_nls_policy::SYSTEM_LCID } else { system };
        let user = if user == 0 { system } else { user };
        let ui = if ui == 0 { language_of(user) } else { ui };
        Self { system, user, ui }
    }

    /// # C: O(1)
    pub fn locale(&self, which: Which) -> u32 { match which { Which::System => self.system, Which::User => self.user } }

    /// The install language follows the system locale, which no service
    /// replaces on its own.
    /// # C: O(1)
    pub fn install_language(&self) -> u16 { language_of(self.system) }
}

/// Admit a query for one of the two locales: the answer needs somewhere to go.
/// # C: O(1)
pub fn admit_locale_query(user: u64, out: u64) -> Result<Which, u64> {
    if out == 0 { return Err(STATUS_ACCESS_VIOLATION); }
    Ok(which_of(user))
}

/// Admit a replacement locale.
/// # C: O(1)
pub fn admit_locale_set(user: u64, lcid: u64) -> (Which, u32) { (which_of(user), lcid as u32) }

/// Admit a query for a language identifier.
/// # C: O(1)
pub fn admit_language_query(out: u64) -> Result<(), u64> {
    if out == 0 { return Err(STATUS_ACCESS_VIOLATION); }
    Ok(())
}

/// The replacement interface language a caller passed; it is 16 bits wide and
/// the rest of the register is not part of it.
/// # C: O(1)
pub fn language_argument(language: u64) -> u16 { language as u16 }

/// Which locale a selector names. The selector is one byte wide and any value
/// but zero names the user's own locale, so no value of it is a caller error.
fn which_of(user: u64) -> Which {
    if crate::nt_obj_sig::boolean(user) { Which::User } else { Which::System }
}

#[cfg(test)]
#[path = "tests/nt_locale.rs"]
mod tests;
