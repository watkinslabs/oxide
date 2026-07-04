use super::*;

const SCHED: &[u8] = b"name: sched_switch\nID: 1\nformat:\n\
\tfield:int common_pid;\toffset:4;\tsize:4;\tsigned:1;\n\
\tfield:char prev_comm[16];\toffset:8;\tsize:16;\tsigned:0;\n\
\tfield:pid_t prev_pid;\toffset:24;\tsize:4;\tsigned:1;\n\
\tfield:char next_comm[16];\toffset:28;\tsize:16;\tsigned:0;\n\
\tfield:pid_t next_pid;\toffset:44;\tsize:4;\tsigned:1;\n";

fn fields() -> Vec<Field> { parse_fields(SCHED) }

#[test]
fn parses_field_table_types() {
    let f = fields();
    let pid = f.iter().find(|x| x.name == "prev_pid").unwrap();
    assert!(!pid.is_string);
    let comm = f.iter().find(|x| x.name == "prev_comm").unwrap();
    assert!(comm.is_string);
    assert_eq!(comm.size, 16);
    let cp = f.iter().find(|x| x.name == "common_pid").unwrap();
    assert!(!cp.is_string);
}

fn rec<'a>(items: &'a [(&'a str, FieldVal<'a>)]) -> EventRecord<'a> { EventRecord::new(items) }

#[test]
fn int_truth_table() {
    let f = fields();
    let a = compile(b"prev_pid == 42", &f).unwrap();
    assert!(evaluate(&a, &rec(&[("prev_pid", FieldVal::Int(42))])));
    assert!(!evaluate(&a, &rec(&[("prev_pid", FieldVal::Int(7))])));
    let a = compile(b"prev_pid > 10", &f).unwrap();
    assert!(evaluate(&a, &rec(&[("prev_pid", FieldVal::Int(11))])));
    assert!(!evaluate(&a, &rec(&[("prev_pid", FieldVal::Int(10))])));
    let a = compile(b"prev_pid <= 10 && prev_pid >= 5", &f).unwrap();
    assert!(evaluate(&a, &rec(&[("prev_pid", FieldVal::Int(5))])));
    assert!(evaluate(&a, &rec(&[("prev_pid", FieldVal::Int(10))])));
    assert!(!evaluate(&a, &rec(&[("prev_pid", FieldVal::Int(11))])));
    let a = compile(b"prev_pid != 0x10", &f).unwrap();
    assert!(!evaluate(&a, &rec(&[("prev_pid", FieldVal::Int(16))])));
    assert!(evaluate(&a, &rec(&[("prev_pid", FieldVal::Int(15))])));
}

#[test]
fn bool_logic_and_precedence() {
    let f = fields();
    let a = compile(b"prev_pid == 1 || prev_pid == 2 && next_pid == 3", &f).unwrap();
    assert!(evaluate(&a, &rec(&[("prev_pid", FieldVal::Int(1)), ("next_pid", FieldVal::Int(99))])));
    assert!(evaluate(&a, &rec(&[("prev_pid", FieldVal::Int(2)), ("next_pid", FieldVal::Int(3))])));
    assert!(!evaluate(&a, &rec(&[("prev_pid", FieldVal::Int(2)), ("next_pid", FieldVal::Int(4))])));
    let a = compile(b"(prev_pid == 1 || prev_pid == 2) && next_pid == 3", &f).unwrap();
    assert!(!evaluate(&a, &rec(&[("prev_pid", FieldVal::Int(1)), ("next_pid", FieldVal::Int(4))])));
    assert!(evaluate(&a, &rec(&[("prev_pid", FieldVal::Int(1)), ("next_pid", FieldVal::Int(3))])));
    let a = compile(b"!(prev_pid == 1)", &f).unwrap();
    assert!(!evaluate(&a, &rec(&[("prev_pid", FieldVal::Int(1))])));
    assert!(evaluate(&a, &rec(&[("prev_pid", FieldVal::Int(2))])));
}

#[test]
fn string_glob_and_eq() {
    let f = fields();
    let a = compile(b"prev_comm ~ \"sh*\"", &f).unwrap();
    assert!(evaluate(&a, &rec(&[("prev_comm", FieldVal::Str("shutdown"))])));
    assert!(!evaluate(&a, &rec(&[("prev_comm", FieldVal::Str("bash"))])));
    let a = compile(b"prev_comm ~ \"*sh\"", &f).unwrap();
    assert!(evaluate(&a, &rec(&[("prev_comm", FieldVal::Str("bash"))])));
    let a = compile(b"next_comm == bash", &f).unwrap();
    assert!(evaluate(&a, &rec(&[("next_comm", FieldVal::Str("bash"))])));
    assert!(!evaluate(&a, &rec(&[("next_comm", FieldVal::Str("dash"))])));
    let a = compile(b"next_comm ~ \"k?orker*\"", &f).unwrap();
    assert!(evaluate(&a, &rec(&[("next_comm", FieldVal::Str("kworker/0"))])));
}

#[test]
fn absent_field_is_false() {
    let f = fields();
    let a = compile(b"prev_pid == 1", &f).unwrap();
    assert!(!evaluate(&a, &rec(&[("next_pid", FieldVal::Int(1))])));
}

#[test]
fn invalid_expressions_rejected() {
    let f = fields();
    assert_eq!(compile(b"nope == 1", &f), Err(ParseError::UnknownField));
    assert_eq!(compile(b"prev_pid =! 1", &f).is_err(), true);
    assert_eq!(compile(b"prev_pid ~ 1", &f), Err(ParseError::TypeMismatch));
    assert_eq!(compile(b"prev_comm < 1", &f), Err(ParseError::TypeMismatch));
    assert_eq!(compile(b"prev_pid == abc", &f), Err(ParseError::BadValue));
    assert_eq!(compile(b"prev_pid ==", &f), Err(ParseError::BadValue));
    assert_eq!(compile(b"prev_pid 1", &f), Err(ParseError::BadOp));
    assert_eq!(compile(b"(prev_pid == 1", &f), Err(ParseError::Syntax));
    assert_eq!(compile(b"prev_pid == 1 prev_pid == 2", &f), Err(ParseError::Trailing));
    assert_eq!(compile(b"", &f), Err(ParseError::Empty));
}

#[test]
fn slot_keeps_prior_on_invalid() {
    static FMT: &[u8] = SCHED;
    let slot = FilterSlot::new(FMT);
    assert!(slot.passes(&rec(&[("prev_pid", FieldVal::Int(5))])));
    slot.set(b"prev_pid == 5\n").unwrap();
    assert!(slot.has_filter());
    assert!(slot.passes(&rec(&[("prev_pid", FieldVal::Int(5))])));
    assert!(!slot.passes(&rec(&[("prev_pid", FieldVal::Int(6))])));
    assert!(slot.set(b"bogus_field == 1\n").is_err());
    assert!(slot.has_filter());
    assert!(slot.passes(&rec(&[("prev_pid", FieldVal::Int(5))])));
    assert!(!slot.passes(&rec(&[("prev_pid", FieldVal::Int(6))])));
    slot.set(b"0\n").unwrap();
    assert!(!slot.has_filter());
    assert!(slot.passes(&rec(&[("prev_pid", FieldVal::Int(6))])));
}

#[test]
fn slot_read_echoes_filter() {
    let slot = FilterSlot::new(SCHED);
    let mut buf = [0u8; 64];
    let n = slot.read_into(0, &mut buf);
    assert_eq!(&buf[..n], b"none\n");
    slot.set(b"prev_pid == 9").unwrap();
    let n = slot.read_into(0, &mut buf);
    assert_eq!(&buf[..n], b"prev_pid == 9\n");
}

#[test]
fn glob_matcher_edges() {
    assert!(glob_match(b"*", b"anything"));
    assert!(glob_match(b"a*c", b"abc"));
    assert!(glob_match(b"a*c", b"ac"));
    assert!(!glob_match(b"a*c", b"ab"));
    assert!(glob_match(b"a?c", b"abc"));
    assert!(!glob_match(b"a?c", b"ac"));
    assert!(glob_match(b"**a", b"xxa"));
}
