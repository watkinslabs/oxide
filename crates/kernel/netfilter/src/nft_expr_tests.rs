// Module manifest (test tree): one child per expression group. Every child is
// bound by an explicit `#[path]` so it resolves against `src/nft_expr_tests/`
// rather than against a sibling implementation file.

#[path = "nft_expr_tests/wire.rs"]      mod wire;
#[path = "nft_expr_tests/lookup.rs"]    mod lookup;
#[path = "nft_expr_tests/fixture.rs"]   pub mod fixture;
#[path = "nft_expr_tests/numbers.rs"]   mod numbers;
#[path = "nft_expr_tests/conn.rs"]      mod conn;
#[path = "nft_expr_tests/rate.rs"]      mod rate;
#[path = "nft_expr_tests/action.rs"]    mod action;
#[path = "nft_expr_tests/select.rs"]    mod select;
#[path = "nft_expr_tests/source.rs"]    mod source;
#[path = "nft_expr_tests/metakeys.rs"]  mod metakeys;
#[path = "nft_expr_tests/hookcheck.rs"] mod hookcheck;
