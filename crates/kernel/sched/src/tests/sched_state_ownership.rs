//! Source-ownership guard for canonical per-task scheduler state.

use std::fs;
use std::{format, vec};
use std::path::{Path, PathBuf};
use std::string::{String, ToString};
use std::vec::Vec;

const OWNER: &str = "task/sched_state.rs";
const SELF: &str = "tests/sched_state_ownership.rs";
const FIELDS: &[&str] = &[
    "class_enc", "nice", "load_weight", "vruntime", "exec_start_ns",
    "sum_exec_runtime_ns", "util_avg", "util_last_update_ns", "nr_migrations",
    "rt_time_slice", "rt_timeout_ns", "sched_reset_on_fork", "sched_slice_ns",
    "uclamp_min", "uclamp_max", "uclamp_user_defined",
    "prio", "static_prio", "normal_prio", "rt_priority", "policy",
    "reset_on_fork", "has_donor", "pi_base_class",
];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Kind { Declaration, DirectAccess }

#[derive(Debug, Eq, PartialEq)]
struct Violation {
    path: PathBuf,
    line: usize,
    field: String,
    kind: Kind,
}

#[derive(Clone, Copy)]
struct Token<'a> {
    text: &'a str,
    line: usize,
}

fn forbidden(name: &str) -> bool { FIELDS.contains(&name) }

fn raw_string_start(bytes: &[u8], at: usize) -> Option<(usize, usize)> {
    let mut i = at;
    if bytes.get(i) == Some(&b'b') { i += 1; }
    if bytes.get(i) != Some(&b'r') { return None; }
    i += 1;
    let mut hashes = 0;
    while bytes.get(i) == Some(&b'#') { hashes += 1; i += 1; }
    if bytes.get(i) != Some(&b'"') { return None; }
    Some((i + 1, hashes))
}

fn sanitize(source: &str) -> String {
    let bytes = source.as_bytes();
    let mut out = bytes.to_vec();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'/' && bytes.get(i + 1) == Some(&b'/') {
            while i < bytes.len() && bytes[i] != b'\n' { out[i] = b' '; i += 1; }
            continue;
        }
        if bytes[i] == b'/' && bytes.get(i + 1) == Some(&b'*') {
            let mut depth = 1;
            out[i] = b' '; out[i + 1] = b' '; i += 2;
            while i < bytes.len() && depth != 0 {
                if bytes[i] == b'/' && bytes.get(i + 1) == Some(&b'*') {
                    depth += 1; out[i] = b' '; out[i + 1] = b' '; i += 2;
                } else if bytes[i] == b'*' && bytes.get(i + 1) == Some(&b'/') {
                    depth -= 1; out[i] = b' '; out[i + 1] = b' '; i += 2;
                } else {
                    if bytes[i] != b'\n' { out[i] = b' '; }
                    i += 1;
                }
            }
            continue;
        }
        if let Some((body, hashes)) = raw_string_start(bytes, i) {
            let mut end = body;
            while end < bytes.len() {
                if bytes[end] == b'"'
                    && (0..hashes).all(|n| bytes.get(end + 1 + n) == Some(&b'#'))
                {
                    end += 1 + hashes;
                    break;
                }
                end += 1;
            }
            while i < end { if bytes[i] != b'\n' { out[i] = b' '; } i += 1; }
            continue;
        }
        if bytes[i] == b'"' {
            out[i] = b' '; i += 1;
            while i < bytes.len() {
                let escaped = bytes[i] == b'\\';
                if bytes[i] != b'\n' { out[i] = b' '; }
                i += 1;
                if escaped && i < bytes.len() {
                    if bytes[i] != b'\n' { out[i] = b' '; }
                    i += 1;
                } else if bytes.get(i.wrapping_sub(1)) == Some(&b'"') { break; }
            }
            continue;
        }
        if bytes[i] == b'\'' {
            let mut end = i + 1;
            let mut closed = false;
            while end < bytes.len() && bytes[end] != b'\n' {
                if bytes[end] == b'\\' { end += 2; continue; }
                if bytes[end] == b'\'' { end += 1; closed = true; break; }
                end += 1;
            }
            if closed {
                while i < end { out[i] = b' '; i += 1; }
                continue;
            }
        }
        i += 1;
    }
    String::from_utf8(out).expect("sanitizing Rust source preserves UTF-8")
}

fn tokens(source: &str) -> Vec<Token<'_>> {
    let bytes = source.as_bytes();
    let mut out = Vec::new();
    let mut line = 1;
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'\n' { line += 1; i += 1; continue; }
        if bytes[i].is_ascii_whitespace() { i += 1; continue; }
        let start = i;
        if bytes[i].is_ascii_alphabetic() || bytes[i] == b'_' {
            i += 1;
            while i < bytes.len() && (bytes[i].is_ascii_alphanumeric() || bytes[i] == b'_') { i += 1; }
        } else { i += 1; }
        out.push(Token { text: &source[start..i], line });
    }
    out
}

fn test_mask(tok: &[Token<'_>]) -> Vec<bool> {
    let mut mask = vec![false; tok.len()];
    let mut i = 0;
    while i + 2 < tok.len() {
        if tok[i].text != "#" || tok[i + 1].text != "[" { i += 1; continue; }
        let mut close = i + 2;
        let mut brackets = 1;
        let mut is_test = false;
        while close < tok.len() && brackets != 0 {
            if tok[close].text == "[" { brackets += 1; }
            if tok[close].text == "]" { brackets -= 1; }
            if tok[close].text == "test" { is_test = true; }
            close += 1;
        }
        if !is_test { i = close; continue; }
        let mut open = close;
        while open < tok.len() && tok[open].text != "{" && tok[open].text != ";" { open += 1; }
        if open == tok.len() || tok[open].text == ";" { i = open.saturating_add(1); continue; }
        let mut end = open + 1;
        let mut braces = 1;
        while end < tok.len() && braces != 0 {
            if tok[end].text == "{" { braces += 1; }
            if tok[end].text == "}" { braces -= 1; }
            end += 1;
        }
        for slot in &mut mask[i..end] { *slot = true; }
        i = end;
    }
    mask
}

fn canonical_chain(tok: &[Token<'_>], mask: &[bool], dot: usize) -> bool {
    let mut i = dot;
    while i > 0 {
        i -= 1;
        if mask[i] { continue; }
        match tok[i].text {
            ";" | "{" | "}" | "," | "=" => return false,
            "sched" if i > 0 && tok[i - 1].text == "." => return true,
            _ => {}
        }
    }
    false
}

fn identifier(text: &str) -> bool {
    text.as_bytes().first().is_some_and(|byte| byte.is_ascii_alphabetic() || *byte == b'_')
        && text.as_bytes().iter().all(|byte| byte.is_ascii_alphanumeric() || *byte == b'_')
}

fn task_bindings<'a>(tok: &[Token<'a>], mask: &[bool]) -> Vec<&'a str> {
    let mut bindings = Vec::new();
    for i in 0..tok.len().saturating_sub(2) {
        if mask[i] || !identifier(tok[i].text) || tok[i + 1].text != ":"
            || (i > 0 && tok[i - 1].text == ":") || tok[i + 2].text == ":"
        {
            continue;
        }
        let mut end = i + 2;
        let mut angles = 0usize;
        let mut is_task = false;
        while end < tok.len() {
            match tok[end].text {
                "<" => angles += 1,
                ">" => angles = angles.saturating_sub(1),
                "Task" | "TaskCore" | "TaskSecurity" => is_task = true,
                "," | ")" | "=" | ";" | "{" if angles == 0 => break,
                _ => {}
            }
            end += 1;
        }
        if is_task && !bindings.contains(&tok[i].text) { bindings.push(tok[i].text); }
    }
    bindings
}

fn task_impl_mask(tok: &[Token<'_>], test: &[bool]) -> Vec<bool> {
    let mut mask = vec![false; tok.len()];
    let mut i = 0;
    while i < tok.len() {
        if test[i] || tok[i].text != "impl" { i += 1; continue; }
        let mut open = i + 1;
        let mut is_task = false;
        while open < tok.len() && tok[open].text != "{" && tok[open].text != ";" {
            if matches!(tok[open].text, "Task" | "TaskCore" | "TaskSecurity") { is_task = true; }
            open += 1;
        }
        if !is_task || open == tok.len() || tok[open].text != "{" {
            i = open.saturating_add(1);
            continue;
        }
        let mut end = open + 1;
        let mut braces = 1;
        while end < tok.len() && braces != 0 {
            if tok[end].text == "{" { braces += 1; }
            if tok[end].text == "}" { braces -= 1; }
            end += 1;
        }
        for slot in &mut mask[open..end] { *slot = true; }
        i = end;
    }
    mask
}

fn task_receiver_chain(
    tok: &[Token<'_>], test: &[bool], task_impl: &[bool], bindings: &[&str], dot: usize,
) -> bool {
    let mut i = dot;
    while i > 0 {
        i -= 1;
        if test[i] { continue; }
        match tok[i].text {
            ";" | "{" | "}" | "," | "=" => return false,
            "self" if task_impl[dot] => return true,
            name if bindings.contains(&name) => return true,
            _ => {}
        }
    }
    false
}

fn scan_source(path: &Path, source: &str) -> Vec<Violation> {
    if path == Path::new(OWNER) || path == Path::new(SELF) { return Vec::new(); }
    let clean = sanitize(source);
    let tok = tokens(&clean);
    let mask = test_mask(&tok);
    let bindings = task_bindings(&tok, &mask);
    let task_impl = task_impl_mask(&tok, &mask);
    let mut out = Vec::new();
    let mut depth = 0usize;
    let mut task_struct_depth = None;
    let mut pending_task_struct = false;
    for i in 0..tok.len() {
        if mask[i] { continue; }
        if tok[i].text == "struct" && i + 1 < tok.len()
            && matches!(tok[i + 1].text, "Task" | "TaskCore" | "TaskSecurity")
        {
            pending_task_struct = true;
        }
        if tok[i].text == "{" {
            depth += 1;
            if pending_task_struct { task_struct_depth = Some(depth); pending_task_struct = false; }
            continue;
        }
        if tok[i].text == "}" {
            if task_struct_depth == Some(depth) { task_struct_depth = None; }
            depth = depth.saturating_sub(1);
            continue;
        }
        if task_struct_depth.is_some() && forbidden(tok[i].text)
            && tok.get(i + 1).map(|t| t.text) == Some(":")
        {
            out.push(Violation { path: path.to_path_buf(), line: tok[i].line,
                field: tok[i].text.to_string(), kind: Kind::Declaration });
        }
        if tok[i].text == "." && i + 1 < tok.len() && forbidden(tok[i + 1].text)
            && tok.get(i + 2).map(|t| t.text) != Some("(")
            && !canonical_chain(&tok, &mask, i)
            && task_receiver_chain(&tok, &mask, &task_impl, &bindings, i)
        {
            out.push(Violation { path: path.to_path_buf(), line: tok[i + 1].line,
                field: tok[i + 1].text.to_string(), kind: Kind::DirectAccess });
        }
    }
    out
}

fn rust_files(root: &Path, dir: &Path, out: &mut Vec<PathBuf>) -> Result<(), String> {
    let entries = fs::read_dir(dir).map_err(|e| format!("{}: {e}", dir.display()))?;
    for entry in entries {
        let path = entry.map_err(|e| format!("{}: {e}", dir.display()))?.path();
        if path.is_dir() {
            if path.file_name().and_then(|n| n.to_str()) != Some("tests") { rust_files(root, &path, out)?; }
        } else if path.extension().and_then(|e| e.to_str()) == Some("rs")
            && path.file_name().and_then(|n| n.to_str()) != Some("tests.rs")
        {
            out.push(path.strip_prefix(root).expect("walk remains below root").to_path_buf());
        }
    }
    Ok(())
}

fn scan_tree(root: &Path) -> Result<Vec<Violation>, String> {
    let mut files = Vec::new();
    rust_files(root, root, &mut files)?;
    files.sort();
    let mut out = Vec::new();
    for rel in files {
        let source = fs::read_to_string(root.join(&rel))
            .map_err(|e| format!("{}: {e}", rel.display()))?;
        out.extend(scan_source(&rel, &source));
    }
    Ok(out)
}

#[test]
fn scheduler_state_has_one_source_of_truth() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let violations = scan_tree(&root).expect("scheduler source tree must be readable");
    let report = violations.iter().map(|v| {
        format!("{}:{}: {:?} `{}`", v.path.display(), v.line, v.kind, v.field)
    }).collect::<Vec<_>>().join("\n");
    assert!(violations.is_empty(), "legacy split scheduler state:\n{report}");
}

fn client_storage_accesses(source: &str) -> Vec<(usize, String)> {
    let sanitized = sanitize(source);
    let tok = tokens(&sanitized);
    let fields = ["se", "rt", "dl", "uclamp_min", "uclamp_max", "uclamp_user_defined"];
    let mut out = Vec::new();
    for (index, pair) in tok.windows(2).enumerate() {
        if pair[0].text != "." || pair[1].text != "sched" { continue; }
        if tok.get(index + 2).is_some_and(|token| token.text == ".") {
            let Some(field) = tok.get(index + 3) else { continue; };
            if fields.contains(&field.text) { out.push((field.line, field.text.to_string())); }
        } else { out.push((pair[1].line, "sched".to_string())); }
    }
    out
}

fn client_rust_files(dir: &Path, sched_root: &Path, out: &mut Vec<PathBuf>) {
    for entry in fs::read_dir(dir).expect("kernel crate tree must be readable") {
        let path = entry.expect("kernel crate entry must be readable").path();
        if path == sched_root { continue; }
        if path.is_dir() { client_rust_files(&path, sched_root, out); }
        else if path.extension().and_then(|e| e.to_str()) == Some("rs") { out.push(path); }
    }
}

#[test]
fn scheduler_clients_cannot_reach_task_sched_storage() {
    assert_eq!(client_storage_accesses("fn bad(t: &mut Task) { t.sched = replacement; }"),
        vec![(1, "sched".to_string())], "whole-state replacement must trip the client gate");
    assert_eq!(client_storage_accesses("fn bad(t: &Task) { t.sched.se.slice.store(1); }"),
        vec![(1, "se".to_string())], "positive control must trip the client gate");
    assert!(client_storage_accesses("fn good(t: &Task) { t.set_sched_slice_ns(1); }").is_empty());

    let sched_root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let kernel_root = sched_root.parent().expect("sched crate is below crates/kernel");
    let mut files = Vec::new();
    client_rust_files(kernel_root, sched_root, &mut files);
    let mut violations = Vec::new();
    for path in files {
        let source = fs::read_to_string(&path).expect("scheduler client source must be readable");
        for (line, field) in client_storage_accesses(&source) {
            violations.push(format!("{}:{line}: direct task.sched.{field}", path.display()));
        }
    }
    assert!(violations.is_empty(), "scheduler clients bypassed typed APIs:\n{}",
        violations.join("\n"));
}

#[test]
fn every_matcher_has_a_synthetic_positive_control() {
    for field in FIELDS {
        let planted = format!(
            "pub struct TaskCore {{\n    pub {field}: AtomicU64,\n}}\n\
             fn read(task: &TaskCore) {{\n\
                 let _ = task.{field}.load();\n\
                 task.{field} = replacement;\n\
                 let _ = (*task).{field};\n\
                 let _ = task.as_ref().{field};\n\
             }}\n\
             impl Task {{ fn read(&self) {{ let _ = self.{field}; }} }}\n"
        );
        let found = scan_source(Path::new("task/core.rs"), &planted);
        assert!(found.iter().any(|v| v.field == *field && v.kind == Kind::Declaration),
            "declaration matcher accepted planted `{field}`");
        assert!(found.iter().any(|v| v.field == *field && v.kind == Kind::DirectAccess),
            "access matcher accepted planted `{field}`");
        assert_eq!(found.iter().filter(|v| v.field == *field
            && v.kind == Kind::DirectAccess).count(), 5,
            "not every planted access to `{field}` was detected");
    }
}

#[test]
fn unrelated_struct_fields_and_receiver_names_are_allowed() {
    for field in FIELDS {
        let unrelated = format!(
            "struct Cand {{ {field}: u64 }}\n\
             fn compare(wakee: Cand, curr: &Cand, task: &Cand) -> bool {{\n\
                 wakee.{field} < curr.{field} || task.{field} == 0\n\
             }}\n"
        );
        assert!(scan_source(Path::new("sched_enc/wakeup.rs"), &unrelated).is_empty(),
            "unrelated `{field}` field was mistaken for Task scheduler state");
    }
}

#[test]
fn canonical_paths_comments_literals_and_test_blocks_are_allowed() {
    let mut caller = String::from("fn read(task: &Task) {\n");
    for field in FIELDS {
        caller.push_str(&format!(" let _ = task.sched.{field};\n"));
        caller.push_str(&format!(" let _ = task.sched.se.{field};\n"));
    }
    caller.push_str("}\n// task.class_enc\nconst TEXT: &str = \"task.vruntime\";\n\
        #[cfg(test)] mod tests { fn legacy(task: &Task) { let _ = task.nice; } }\n");
    assert!(scan_source(Path::new("live/read.rs"), &caller).is_empty());

    let mut owner = String::new();
    for field in FIELDS { owner.push_str(&format!("fn f(s: &State) {{ let _ = s.{field}; }}\n")); }
    assert!(scan_source(Path::new(OWNER), &owner).is_empty());
}
