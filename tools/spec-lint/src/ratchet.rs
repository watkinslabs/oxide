// Ratchet gate: spec-lint findings may never grow, per unit + rule.
//
// The full lint carries a large historical backlog, so `make lint` cannot be a
// push gate today. What CAN be a gate is the derivative: a snapshot of the
// count per (unit, rule) that the tool refuses to let increase. New violations
// fail even in a unit that already has hundreds, because the comparison is
// per-unit, not per-tree.
//
// Unit = the crate that owns the file (nearest ancestor directory holding a
// `Cargo.toml`), or the top-level directory when no crate owns it. Crate
// granularity is deliberate: `docs/08§7` forces files to split at 500 lines, so
// a file-keyed baseline would go red on every routine split while a tree-keyed
// one would let a new violation hide behind an unrelated fix.
//
// The baseline may only SHRINK. `--update` writes `min(current, baseline)` for
// every key and never raises one; raising requires `--allow-growth`, which
// prints a loud warning naming every key it loosened.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use crate::Findings;

pub const BASELINE_REL: &str = "tools/spec-lint/baseline.tsv";

const HEADER: &str = "\
# spec-lint ratchet baseline. Counts are per (unit, rule) and may only DECREASE.
# Regenerate with `make lint-ratchet-update` after fixing findings.
# Raising a count requires `spec-lint ratchet --update --allow-growth` and is a
# policy decision, not a routine step: it retires enforcement this gate already had.
# unit\trule\tcount
";

pub type Counts = BTreeMap<(String, String), usize>;

/// Aggregate findings into per-(unit, rule) counts.
pub fn tally(root: &Path, f: &Findings) -> Counts {
    let mut out: Counts = BTreeMap::new();
    for item in f.items() {
        let unit = unit_of(root, &item.path);
        *out.entry((unit, item.rule.to_string())).or_insert(0) += 1;
    }
    out
}

/// Crate directory owning `path`, relative to `root`; else its first component.
fn unit_of(root: &Path, path: &Path) -> String {
    let rel = path.strip_prefix(root).unwrap_or(path);
    let mut dir = rel.parent();
    while let Some(d) = dir {
        if d.as_os_str().is_empty() { break; }
        if root.join(d).join("Cargo.toml").is_file() {
            return d.to_string_lossy().replace('\\', "/");
        }
        dir = d.parent();
    }
    match rel.components().next() {
        Some(c) => c.as_os_str().to_string_lossy().into_owned(),
        None => "<root>".into(),
    }
}

pub fn load(path: &Path) -> Counts {
    let mut out: Counts = BTreeMap::new();
    let Ok(text) = fs::read_to_string(path) else { return out };
    for l in text.lines() {
        let l = l.trim_end();
        if l.is_empty() || l.starts_with('#') { continue; }
        let mut it = l.split('\t');
        let (Some(unit), Some(rule), Some(n)) = (it.next(), it.next(), it.next()) else { continue };
        let Ok(n) = n.trim().parse::<usize>() else { continue };
        out.insert((unit.to_string(), rule.to_string()), n);
    }
    out
}

pub fn render(counts: &Counts) -> String {
    let mut s = String::from(HEADER);
    for ((unit, rule), n) in counts {
        s.push_str(unit); s.push('\t'); s.push_str(rule); s.push('\t');
        s.push_str(&n.to_string()); s.push('\n');
    }
    s
}

pub fn total(counts: &Counts) -> usize { counts.values().sum() }

pub enum Outcome { Pass, Fail }

/// Keys whose current count exceeds baseline, as `(key, baseline, current)`.
/// Absent from baseline = 0, so a brand-new unit or rule is a regression.
/// Per-key, so a fix in one rule can never pay for a new violation of another.
pub fn regressions<'a>(cur: &'a Counts, base: &Counts) -> Vec<(&'a (String, String), usize, usize)> {
    let mut out = Vec::new();
    for (k, n) in cur {
        let b = base.get(k).copied().unwrap_or(0);
        if *n > b { out.push((k, b, *n)); }
    }
    out
}

/// Compare `cur` against the stored baseline; report and (optionally) rewrite.
pub fn check(root: &Path, cur: &Counts, update: bool, allow_growth: bool) -> Outcome {
    let bpath = root.join(BASELINE_REL);
    let base = load(&bpath);
    if base.is_empty() && !update {
        eprintln!("spec-lint ratchet: no baseline at {} — run `make lint-ratchet-update`", bpath.display());
        return Outcome::Fail;
    }

    let over = regressions(cur, &base);
    let mut under = 0usize;
    for (k, b) in &base {
        let n = cur.get(k).copied().unwrap_or(0);
        if n < *b { under += b - n; }
    }

    if update { return write_baseline(&bpath, cur, &base, allow_growth); }

    for (k, b, n) in &over {
        eprintln!("spec-lint ratchet: REGRESSION {} [{}] {} > {} (baseline)", k.0, k.1, n, b);
    }
    println!("spec-lint ratchet: {} finding(s) across {} unit+rule key(s); baseline total {}",
             total(cur), cur.len(), total(&base));
    if !over.is_empty() {
        eprintln!("spec-lint ratchet: FAIL — {} key(s) above baseline. Fix the new finding(s);", over.len());
        eprintln!("        the baseline is a ratchet, not a waiver list — it does not grow.");
        return Outcome::Fail;
    }
    if under > 0 {
        eprintln!("spec-lint ratchet: FAIL — {under} finding(s) below baseline and NOT locked in.");
        eprintln!("        Run `make lint-ratchet-update` and commit the baseline in THIS PR.");
        eprintln!("        A ratchet that is never tightened is only a high-water mark: those");
        eprintln!("        {under} fixed finding(s) could be reintroduced and the gate would stay green.");
        return Outcome::Fail;
    }
    println!("spec-lint ratchet: PASS — at baseline");
    Outcome::Pass
}

fn write_baseline(bpath: &PathBuf, cur: &Counts, base: &Counts, allow_growth: bool) -> Outcome {
    let mut next: Counts = BTreeMap::new();
    let mut grown: Vec<(&(String, String), usize, usize)> = Vec::new();
    // Union of both key sets: a key that dropped to zero disappears entirely.
    for (k, n) in cur {
        let b = base.get(k).copied();
        match b {
            Some(b) if *n > b => { grown.push((k, b, *n)); next.insert(k.clone(), if allow_growth { *n } else { b }); }
            Some(b) => { next.insert(k.clone(), (*n).min(b)); }
            None => { grown.push((k, 0, *n)); if allow_growth { next.insert(k.clone(), *n); } }
        }
    }
    if !grown.is_empty() && !allow_growth {
        for (k, b, n) in &grown {
            eprintln!("spec-lint ratchet: REFUSED to raise {} [{}] {} -> {}", k.0, k.1, b, n);
        }
        eprintln!("spec-lint ratchet: FAIL — --update never raises a count. Fix the finding(s),");
        eprintln!("        or pass --allow-growth if retiring this enforcement is intended.");
        return Outcome::Fail;
    }
    if !grown.is_empty() {
        eprintln!("!!! spec-lint ratchet: --allow-growth RAISED {} key(s). Enforcement this gate", grown.len());
        eprintln!("!!! already had is now retired for them. Every line below is a regression");
        eprintln!("!!! being accepted on purpose:");
        for (k, b, n) in &grown { eprintln!("!!!   {} [{}] {} -> {}", k.0, k.1, b, n); }
    }
    if let Err(e) = fs::write(bpath, render(&next)) {
        eprintln!("spec-lint ratchet: write {}: {e}", bpath.display());
        return Outcome::Fail;
    }
    println!("spec-lint ratchet: wrote {} ({} key(s), {} finding(s))",
             bpath.display(), next.len(), total(&next));
    Outcome::Pass
}

#[cfg(test)]
mod tests;
