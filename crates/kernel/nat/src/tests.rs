// Module manifest (test tree): one child per behaviour group, each bound by an
// explicit `#[path]` so it resolves against `src/tests/`.

#[path = "tests/range.rs"]  mod range;
#[path = "tests/unique.rs"] mod unique;
#[path = "tests/binding.rs"] mod binding;
#[path = "tests/manip.rs"]  mod manip;
#[path = "tests/policy.rs"] mod policy;
