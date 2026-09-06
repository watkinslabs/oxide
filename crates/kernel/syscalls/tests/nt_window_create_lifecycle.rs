#[path = "../src/nt_window/create_lifecycle.rs"]
mod create_lifecycle;

use create_lifecycle::{after_create, after_nc_create, CreateStructArgs, CreateTransition};

#[test]
fn callback_results_have_windows_failure_semantics() {
    assert_eq!(after_nc_create(0), CreateTransition::Reject);
    assert_eq!(after_nc_create(1), CreateTransition::Continue);
    assert_eq!(after_create(u64::MAX), CreateTransition::Reject);
    assert_eq!(after_create(0), CreateTransition::Commit);
}

#[test]
fn create_struct_keeps_pointer_and_scalar_fields_separate() {
    let value = CreateStructArgs {
        lp_create_params: 1,
        instance: 2,
        menu: 3,
        parent: 4,
        cy: -5,
        cx: 6,
        y: -7,
        x: 8,
        style: -9,
        name: 10,
        class: 11,
        ex_style: 12,
    };
    assert_eq!(value.cy, -5);
    assert_eq!(value.style, -9);
    assert_eq!(value.class, 11);
}
