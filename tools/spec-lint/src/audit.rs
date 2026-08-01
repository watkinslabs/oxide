// Audit-facing counts for the SCOPED code rules (`docs/07§5`).
//
// Why this exists: `07§5`'s rules bind the kernel BINARY, so `code_lint` filters
// out lines no kernel build compiles (`#[cfg(test)]` items,
// `#[cfg(not(target_os = "oxide-kernel"))]`, dev-only crates — see
// `code_lint::scope`). A `grep -c` does not filter that way, so it returns a
// number that is both much larger and, read as a violation count, simply wrong.
//
// That mistake has been made: `extern crate std` was escalated as ~18-73
// violations and `panic!(fmt)` as 113, when the enforced counts are 0 and 0.
// This report prints BOTH numbers side by side, so an audit can see the raw
// figure it would have quoted and the enforced figure that is the rule.
//
// It is a gate, not just a report: the scoped rules are at zero, and this fails
// if any of them leaves zero.

use std::path::Path;

use crate::{code_lint, walk, read, Findings};

/// One scoped rule: its lint id, the naive pattern an auditor would grep, and a
/// note explaining the gap when the two counts differ.
struct Rule {
    id: &'static str,
    grep: &'static str,
    raw: fn(&str) -> bool,
    why: &'static str,
}

fn raw_extern_std(line: &str) -> bool { line.trim_start().starts_with("extern crate std") }

fn raw_panic_fmt(line: &str) -> bool {
    let Some(idx) = line.find("panic!(") else { return false };
    let rest = &line[idx + "panic!(".len()..];
    rest.contains('{') && rest.contains('}')
}

fn raw_static_mut(line: &str) -> bool {
    let code = match line.find("//") { Some(i) => &line[..i], None => line };
    code.contains("static mut ")
}

const RULES: &[Rule] = &[
    Rule {
        id: "code/extern-std",
        grep: "^\\s*extern crate std",
        raw: raw_extern_std,
        why: "gated by target cfg, `feature = \"hosted\"`, an enclosing `#[cfg(test)] mod`, \
              or a dev-only crate under the `02` carve-out — no kernel binary contains them",
    },
    Rule {
        id: "code/panic-fmt",
        grep: "panic!\\(.*\\{",
        raw: raw_panic_fmt,
        why: "host test code, where `assert_eq!` expands to exactly this construct",
    },
    Rule {
        id: "code/static-mut",
        grep: "static mut ",
        raw: raw_static_mut,
        why: "`#[cfg(test)]` items, plus `&'static mut T` reference types the grep cannot \
              tell from a `static mut` item",
    },
];

/// Print raw-vs-enforced for every scoped rule. `true` when all are at zero.
pub fn run(root: &Path) -> bool {
    let mut f = Findings::default();
    code_lint::run(root, &mut f);

    let mut raw_totals = [0usize; 3];
    for sub in &["crates", "kernel"] {
        let d = root.join(sub);
        if !d.is_dir() { continue; }
        for p in walk::files_with_ext(&d, "rs", &["target"]) {
            let text = read(&p);
            for line in text.lines() {
                for (i, r) in RULES.iter().enumerate() {
                    if (r.raw)(line) { raw_totals[i] += 1; }
                }
            }
        }
    }

    println!("spec-lint audit: scoped rules (`docs/07§5` binds the KERNEL BUILD)");
    println!();
    println!("  {:<18} {:>8} {:>9}  {}", "rule", "enforced", "raw grep", "grep pattern");
    let mut clean = true;
    for (i, r) in RULES.iter().enumerate() {
        let enforced = f.items().iter().filter(|x| x.rule == r.id).count();
        if enforced > 0 { clean = false; }
        println!("  {:<18} {:>8} {:>9}  {}", r.id, enforced, raw_totals[i], r.grep);
    }
    println!();
    for (i, r) in RULES.iter().enumerate() {
        let enforced = f.items().iter().filter(|x| x.rule == r.id).count();
        if raw_totals[i] > enforced {
            println!("  {}: {} raw match(es) are out of scope — {}.",
                r.id, raw_totals[i] - enforced, r.why);
        }
    }
    println!();
    if clean {
        println!("spec-lint audit: PASS — every scoped rule is at zero.");
        println!("        Quote the `enforced` column. The raw column is what a `grep -c` returns");
        println!("        and is NOT a violation count.");
    } else {
        eprintln!("spec-lint audit: FAIL — a scoped rule left zero. See `code` output for sites.");
    }
    clean
}

#[cfg(test)]
mod tests {
    use super::{raw_extern_std, raw_panic_fmt, raw_static_mut};

    #[test]
    fn the_raw_matchers_see_what_a_grep_would_see_including_out_of_scope_lines() {
        // The point of the raw column is that it does NOT filter. These are all
        // compliant sites, and the raw matcher must still count them — otherwise
        // the report cannot show the gap it exists to explain.
        assert!(raw_extern_std("    extern crate std;"));
        assert!(raw_extern_std("extern crate std;"));
        assert!(raw_panic_fmt(r#"    let i = x.unwrap_or_else(|| panic!("{} minted", path));"#));
        assert!(raw_static_mut("    static mut COUNTER: u64 = 0;"));
    }

    #[test]
    fn a_raw_matcher_does_not_fire_on_unrelated_text() {
        assert!(!raw_extern_std("// extern crate std is forbidden"));
        assert!(!raw_panic_fmt(r#"    panic!("plain literal");"#));
        assert!(!raw_static_mut("// static mut is banned"));
        assert!(!raw_panic_fmt("    kassert!(cond, \"literal\");"));
    }

    #[test]
    fn a_reference_type_is_not_a_static_mut_item_but_the_raw_grep_cannot_tell() {
        // Exactly the gap the `why` note names: the raw column over-counts here
        // and the enforced column does not.
        assert!(raw_static_mut("fn f(p: &'static mut [u8]) {}"));
    }
}
