// Module manifest (test tree): one child per behaviour group, bound by an
// explicit `#[path]` so each resolves against `src/tests/`.

#[path = "tests/nla.rs"]      mod nla;
#[path = "tests/msg.rs"]      mod msg;
#[path = "tests/registry.rs"] mod registry;
