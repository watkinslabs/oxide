// Service-manager unit parser. Parses systemd-shape `.service`
// unit files into a `Unit` struct that the manager loop can act on.
//
// Subset supported in v1:
//   [Unit]
//     Description=
//     After=             (whitespace-separated unit names)
//     Requires=
//   [Service]
//     ExecStart=         (absolute path + space-separated argv)
//     ExecStop=
//     Type=              (simple | oneshot | forking)
//     Restart=           (no | always | on-failure)
//     User=
//     Group=
//     Environment=       (KEY=VAL, may repeat)
//     WorkingDirectory=
//   [Install]
//     WantedBy=
//
// Lines beginning with `#` or `;` are comments. Blank lines and
// unknown keys are ignored (forward-compat with extra systemd
// fields). Section headers are case-sensitive (matches systemd).
//
// Out of scope for v1: line continuations (`\` at EOL),
// per-section duplicates merging, drop-in directories
// (`*.service.d/`), templating (`@`), socket/timer units.

#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]

#[cfg(any(test, feature = "hosted"))]
extern crate std;

extern crate alloc;
use alloc::string::{String, ToString};
use alloc::vec::Vec;

pub mod supervisor;
pub use supervisor::{Action, State, Supervisor, RESTART_BACKOFF_TICKS};

#[derive(Copy, Clone, Debug, Eq, PartialEq, Default)]
pub enum ServiceType {
    #[default]
    Simple,
    Oneshot,
    Forking,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq, Default)]
pub enum RestartPolicy {
    #[default]
    No,
    Always,
    OnFailure,
}

#[derive(Clone, Debug, Default)]
pub struct Unit {
    pub name:        String,
    pub description: String,
    pub after:       Vec<String>,
    pub requires:    Vec<String>,
    pub exec_start:  Vec<String>,    // argv (path + args)
    pub exec_stop:   Vec<String>,
    pub kind:        ServiceType,
    pub restart:     RestartPolicy,
    pub user:        String,
    pub group:       String,
    pub env:         Vec<(String, String)>,
    pub working_dir: String,
    pub wanted_by:   Vec<String>,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum ParseError {
    BadHeader,
    UnknownType,
    UnknownRestart,
    EmptyExec,
}

/// Parse a single `.service` file. `name` should be the unit name
/// (e.g. `"sshd.service"`); the parser does not derive it from
/// the filename so the caller stays in control.
/// # C: O(file_size)
pub fn parse(name: &str, body: &str) -> Result<Unit, ParseError> {
    let mut u = Unit::default();
    u.name = name.to_string();
    let mut section = "";
    for raw in body.lines() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with(';') { continue; }
        if let Some(s) = line.strip_prefix('[') {
            let s = s.strip_suffix(']').ok_or(ParseError::BadHeader)?;
            section = match s {
                "Unit" => "Unit",
                "Service" => "Service",
                "Install" => "Install",
                _ => "", // ignore unknown sections
            };
            continue;
        }
        let (k, v) = match line.split_once('=') {
            Some(t) => t, None => continue,
        };
        let k = k.trim();
        let v = v.trim();
        match (section, k) {
            ("Unit", "Description") => u.description = v.to_string(),
            ("Unit", "After")       => u.after.extend(split_ws(v)),
            ("Unit", "Requires")    => u.requires.extend(split_ws(v)),

            ("Service", "ExecStart")        => u.exec_start = split_argv(v),
            ("Service", "ExecStop")         => u.exec_stop  = split_argv(v),
            ("Service", "Type") => {
                u.kind = match v {
                    "simple"  => ServiceType::Simple,
                    "oneshot" => ServiceType::Oneshot,
                    "forking" => ServiceType::Forking,
                    _         => return Err(ParseError::UnknownType),
                };
            }
            ("Service", "Restart") => {
                u.restart = match v {
                    "no"         => RestartPolicy::No,
                    "always"     => RestartPolicy::Always,
                    "on-failure" => RestartPolicy::OnFailure,
                    _            => return Err(ParseError::UnknownRestart),
                };
            }
            ("Service", "User")             => u.user = v.to_string(),
            ("Service", "Group")            => u.group = v.to_string(),
            ("Service", "WorkingDirectory") => u.working_dir = v.to_string(),
            ("Service", "Environment")      => {
                if let Some((ek, ev)) = v.split_once('=') {
                    u.env.push((ek.trim().to_string(), ev.trim().to_string()));
                }
            }

            ("Install", "WantedBy") => u.wanted_by.extend(split_ws(v)),

            _ => { /* ignore */ }
        }
    }
    if matches!(u.kind, ServiceType::Simple | ServiceType::Forking) && u.exec_start.is_empty() {
        return Err(ParseError::EmptyExec);
    }
    Ok(u)
}

fn split_ws(s: &str) -> Vec<String> {
    s.split_whitespace().map(|x| x.to_string()).collect()
}
fn split_argv(s: &str) -> Vec<String> {
    s.split_whitespace().map(|x| x.to_string()).collect()
}

/// Topological sort of units by `after` dependency edges (Kahn).
/// Returns the start order; Err on cycle.
/// # C: O(V + E)
pub fn order(units: &[Unit]) -> Result<Vec<String>, &'static str> {
    use alloc::collections::BTreeMap;
    let mut indeg: BTreeMap<&str, usize> = BTreeMap::new();
    for u in units { indeg.insert(&u.name, 0); }
    for u in units {
        for dep in &u.after {
            if indeg.contains_key(dep.as_str()) {
                *indeg.entry(u.name.as_str()).or_insert(0) += 1;
            }
        }
    }
    let mut ready: Vec<&str> = indeg.iter().filter(|(_, &d)| d == 0).map(|(n, _)| *n).collect();
    let mut out = Vec::new();
    while let Some(n) = ready.pop() {
        out.push(n.to_string());
        // any unit that lists `n` in `after` decrements its indegree
        for u in units {
            if u.after.iter().any(|x| x == n) {
                if let Some(d) = indeg.get_mut(u.name.as_str()) {
                    if *d > 0 { *d -= 1; if *d == 0 { ready.push(u.name.as_str()); } }
                }
            }
        }
    }
    if out.len() != units.len() { return Err("dependency cycle"); }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_minimal_unit() {
        let body = "\
[Unit]
Description=Test daemon

[Service]
ExecStart=/usr/bin/foo --flag arg
Type=simple
Restart=on-failure
User=daemon
Environment=PATH=/bin:/usr/bin
Environment=LOG=info

[Install]
WantedBy=multi-user.target
";
        let u = parse("foo.service", body).unwrap();
        assert_eq!(u.description, "Test daemon");
        assert_eq!(u.exec_start, alloc::vec!["/usr/bin/foo", "--flag", "arg"]);
        assert_eq!(u.kind, ServiceType::Simple);
        assert_eq!(u.restart, RestartPolicy::OnFailure);
        assert_eq!(u.user, "daemon");
        assert_eq!(u.env.len(), 2);
        assert_eq!(u.wanted_by, alloc::vec!["multi-user.target"]);
    }

    #[test]
    fn rejects_simple_without_exec_start() {
        let body = "[Service]\nType=simple\n";
        assert_eq!(parse("x.service", body).unwrap_err(), ParseError::EmptyExec);
    }

    #[test]
    fn allows_oneshot_without_exec_start() {
        let body = "[Service]\nType=oneshot\n";
        assert!(parse("x.service", body).is_ok());
    }

    #[test]
    fn ignores_unknown_keys_and_sections() {
        let body = "\
[X-Custom]
Foo=bar

[Service]
ExecStart=/x
SomethingNew=1
";
        let u = parse("x.service", body).unwrap();
        assert_eq!(u.exec_start, alloc::vec!["/x"]);
    }

    #[test]
    fn comments_and_blank_lines() {
        let body = "\
# leading comment
; alt comment

[Service]
# nested
ExecStart=/x
";
        assert!(parse("x.service", body).is_ok());
    }

    #[test]
    fn rejects_unknown_type() {
        let body = "[Service]\nType=quirky\nExecStart=/x\n";
        assert_eq!(parse("x.service", body).unwrap_err(), ParseError::UnknownType);
    }

    #[test]
    fn topo_order_resolves_chain() {
        let mk = |n: &str, after: &[&str]| {
            let mut u = Unit::default();
            u.name = n.to_string();
            u.kind = ServiceType::Oneshot;
            u.after = after.iter().map(|x| x.to_string()).collect();
            u
        };
        let units = alloc::vec![
            mk("c", &["b"]),
            mk("a", &[]),
            mk("b", &["a"]),
        ];
        let order = order(&units).unwrap();
        let pos = |n: &str| order.iter().position(|x| x == n).unwrap();
        assert!(pos("a") < pos("b"));
        assert!(pos("b") < pos("c"));
    }

    #[test]
    fn topo_detects_cycle() {
        let mk = |n: &str, after: &[&str]| {
            let mut u = Unit::default();
            u.name = n.to_string();
            u.kind = ServiceType::Oneshot;
            u.after = after.iter().map(|x| x.to_string()).collect();
            u
        };
        let units = alloc::vec![mk("a", &["b"]), mk("b", &["a"])];
        assert!(order(&units).is_err());
    }
}
