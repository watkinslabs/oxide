// Hosted tests for the zone machinery. Test-module manifest: each child is
// bound by an explicit path so a bare `mod` can never resolve to the
// implementation file of the same name.

#[path = "tests/gfp.rs"] mod gfp;
#[path = "tests/limits.rs"] mod limits;
#[path = "tests/zonelist.rs"] mod zonelist;
#[path = "tests/reserve.rs"] mod reserve;
#[path = "tests/wmark.rs"] mod wmark;
