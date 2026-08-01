use super::*;

#[test]
fn export_symbols_registers_configfs_surface() {
    let _modules = crate::test_serial::claim();
    let _serial = TEST_SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    export_symbols();
    assert!(crate::is_exported("configfs_register_subsystem"));
    assert!(crate::is_exported("configfs_unregister_group"));
    assert!(crate::is_exported("config_item_set_name"));
    assert!(crate::is_exported("config_item_get_unless_zero"));
    assert!(crate::is_exported("configfs_depend_item"));
    assert!(crate::is_exported("configfs_create_link"));
}

