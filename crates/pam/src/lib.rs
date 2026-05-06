// PAM-shape pluggable authentication. Real PAM is a runtime-loaded
// module stack; v1 is a compiled-in stack with the same surface
// shape: callers ask `authenticate(service, username, password)`,
// the lib walks the service's configured stack of `AuthStep`s
// and returns Allow/Deny/User reasons. Sufficient for `login`,
// `su`, `passwd` to do the right thing without hand-rolling
// shadow file parsing in each binary.
//
// /etc/pam.d/<service> is parsed at boot into ServiceStack; default
// stacks are baked in for `login`, `su`, `passwd`, `sshd`.

#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]

#[cfg(any(test, feature = "hosted"))]
extern crate std;

extern crate alloc;
use alloc::string::{String, ToString};
use alloc::vec::Vec;

use nss::{Passwd, Shadow};

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum AuthResult {
    /// User authenticated successfully.
    Allow,
    /// User exists but password did not match.
    BadPassword,
    /// User does not exist.
    NoSuchUser,
    /// Account locked (e.g., shadow hash starts with `!` or `*`).
    Locked,
    /// Account expired (shadow `expire` field has passed).
    Expired,
    /// Service unknown.
    NoService,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum Control {
    /// Failure aborts the stack with denial.
    Required,
    /// Failure aborts immediately.
    Requisite,
    /// Success short-circuits the stack with allow.
    Sufficient,
    /// Failure is ignored.
    Optional,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum Module {
    /// Look up user in /etc/passwd; no password check.
    UnixAccount,
    /// Verify password against /etc/shadow via crypt::verify.
    UnixAuth,
    /// Always-deny — terminator for "user not found" paths.
    Deny,
    /// Always-allow — terminator for sufficient-prefixed lines.
    Permit,
}

#[derive(Clone, Debug)]
pub struct Step {
    pub control: Control,
    pub module:  Module,
}

#[derive(Clone, Debug, Default)]
pub struct ServiceStack {
    pub name: String,
    pub stack: Vec<Step>,
}

/// Bundle of state PAM needs to evaluate a stack. Keeps the API
/// pure — no globals, no FS reads. Caller hands in the parsed
/// passwd/shadow tables (typically read once at boot).
pub struct Ctx<'a> {
    pub passwd: &'a [Passwd],
    pub shadow: &'a [Shadow],
    /// Days since epoch for `expire` checks; -1 disables.
    pub today_days: i64,
}

impl<'a> Ctx<'a> {
    pub fn new(passwd: &'a [Passwd], shadow: &'a [Shadow]) -> Self {
        Self { passwd, shadow, today_days: -1 }
    }
}

/// Bake-in the canonical default stacks. Equivalent to:
///   /etc/pam.d/login   ->  required unix_account ; required unix_auth
///   /etc/pam.d/su      ->  required unix_account ; sufficient unix_auth ; required deny
///   /etc/pam.d/passwd  ->  required unix_account
///   /etc/pam.d/sshd    ->  required unix_account ; required unix_auth
pub fn default_stacks() -> Vec<ServiceStack> {
    use {Control::*, Module::*};
    let mk = |name: &str, steps: &[(Control, Module)]| ServiceStack {
        name: name.to_string(),
        stack: steps.iter().map(|(c, m)| Step { control: *c, module: *m }).collect(),
    };
    alloc::vec![
        mk("login",  &[(Required, UnixAccount), (Required,   UnixAuth)]),
        mk("su",     &[(Required, UnixAccount), (Sufficient, UnixAuth), (Required, Deny)]),
        mk("passwd", &[(Required, UnixAccount)]),
        mk("sshd",   &[(Required, UnixAccount), (Required,   UnixAuth)]),
    ]
}

/// Lookup helper.
pub fn find_service<'a>(stacks: &'a [ServiceStack], name: &str) -> Option<&'a ServiceStack> {
    stacks.iter().find(|s| s.name == name)
}

/// Walk the configured stack for `service` against (username, password).
/// # C: O(stack_len × user_table)
pub fn authenticate(
    stacks:   &[ServiceStack],
    ctx:      &Ctx<'_>,
    service:  &str,
    username: &str,
    password: &str,
) -> AuthResult {
    let stack = match find_service(stacks, service) {
        Some(s) => s, None => return AuthResult::NoService,
    };
    let mut final_result = AuthResult::Allow;
    for step in &stack.stack {
        let r = run_module(step.module, ctx, username, password);
        let success = matches!(r, AuthResult::Allow);
        match step.control {
            Control::Required => {
                if !success && final_result == AuthResult::Allow {
                    final_result = r;
                }
            }
            Control::Requisite => {
                if !success { return r; }
            }
            Control::Sufficient => {
                if success { return AuthResult::Allow; }
            }
            Control::Optional => { /* ignore failure */ }
        }
    }
    final_result
}

fn run_module(m: Module, ctx: &Ctx<'_>, user: &str, password: &str) -> AuthResult {
    match m {
        Module::UnixAccount => {
            let p = match nss::getpwnam(ctx.passwd, user) {
                Some(p) => p, None => return AuthResult::NoSuchUser,
            };
            let _ = p;
            AuthResult::Allow
        }
        Module::UnixAuth => {
            let s = match nss::getspnam(ctx.shadow, user) {
                Some(s) => s, None => return AuthResult::NoSuchUser,
            };
            let h = &s.passwd_hash;
            if h.starts_with('!') || h.starts_with('*') { return AuthResult::Locked; }
            if ctx.today_days >= 0 && s.expire >= 0 && ctx.today_days >= s.expire {
                return AuthResult::Expired;
            }
            match crypt::verify(password, h) {
                crypt::CryptResult::Match | crypt::CryptResult::NoPassword => AuthResult::Allow,
                _ => AuthResult::BadPassword,
            }
        }
        Module::Deny   => AuthResult::BadPassword,
        Module::Permit => AuthResult::Allow,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use nss::{Passwd, Shadow};

    fn fixt() -> (Vec<Passwd>, Vec<Shadow>) {
        let pw = nss::parse_passwd(b"root:x:0:0:root:/root:/bin/sh\nalice:x:1000:1000:Alice:/home/alice:/bin/sh\nlocked:x:1001:1001:::/bin/sh\nempty:x:1002:1002:::/bin/sh\n");
        // root: $6$rootsalt$<sha512crypt(password=letmein)>
        // alice: $6$alsalt$<sha512crypt(password=swordfish)>
        // locked: ! prefix
        // empty: empty hash → NoPassword
        let root_h   = crypt::sha512::sha512crypt(b"letmein",   b"rootsalt", 5000);
        let alice_h  = crypt::sha512::sha512crypt(b"swordfish", b"alsalt",   5000);
        let shadow_text = std::format!(
            "root:$6$rootsalt${}:19000:0:99999:7:::\nalice:$6$alsalt${}:19000:0:99999:7:::\nlocked:!:19000:0:99999:7:::\nempty::19000:0:99999:7:::\n",
            root_h, alice_h);
        let sh = nss::parse_shadow(shadow_text.as_bytes());
        (pw, sh)
    }

    #[test]
    fn login_happy_path() {
        let (pw, sh) = fixt();
        let stacks = default_stacks();
        let ctx = Ctx::new(&pw, &sh);
        assert_eq!(authenticate(&stacks, &ctx, "login", "alice", "swordfish"), AuthResult::Allow);
    }

    #[test]
    fn login_bad_password() {
        let (pw, sh) = fixt();
        let stacks = default_stacks();
        let ctx = Ctx::new(&pw, &sh);
        assert_eq!(authenticate(&stacks, &ctx, "login", "alice", "wrong"), AuthResult::BadPassword);
    }

    #[test]
    fn login_no_such_user() {
        let (pw, sh) = fixt();
        let stacks = default_stacks();
        let ctx = Ctx::new(&pw, &sh);
        assert_eq!(authenticate(&stacks, &ctx, "login", "ghost", "x"), AuthResult::NoSuchUser);
    }

    #[test]
    fn login_locked_account() {
        let (pw, sh) = fixt();
        let stacks = default_stacks();
        let ctx = Ctx::new(&pw, &sh);
        assert_eq!(authenticate(&stacks, &ctx, "login", "locked", ""), AuthResult::Locked);
    }

    #[test]
    fn empty_hash_no_password_login() {
        let (pw, sh) = fixt();
        let stacks = default_stacks();
        let ctx = Ctx::new(&pw, &sh);
        assert_eq!(authenticate(&stacks, &ctx, "login", "empty", ""), AuthResult::Allow);
    }

    #[test]
    fn no_service() {
        let (pw, sh) = fixt();
        let stacks = default_stacks();
        let ctx = Ctx::new(&pw, &sh);
        assert_eq!(authenticate(&stacks, &ctx, "ftpd", "alice", "x"), AuthResult::NoService);
    }

    #[test]
    fn passwd_service_only_account() {
        // /etc/pam.d/passwd has unix_account but no unix_auth — even
        // wrong password is accepted (root changes other users).
        let (pw, sh) = fixt();
        let stacks = default_stacks();
        let ctx = Ctx::new(&pw, &sh);
        assert_eq!(authenticate(&stacks, &ctx, "passwd", "alice", "anything"), AuthResult::Allow);
    }
}
