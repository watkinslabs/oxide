use super::*;
use alloc::boxed::Box;

#[test]
fn a_packed_identifier_decodes_to_its_text_form() {
    assert_eq!(eisa_id_to_string(0x0A0C_D041), "PNP0C0A");
    assert_eq!(eisa_id_to_string(0x0000_D041), "PNP0000");
    assert_eq!(eisa_id_to_string(0x0303_D041), "PNP0303");
}

#[test]
fn an_integer_field_still_yields_a_text_identity() {
    assert_eq!(AmlField::Int(42).text(), "42");
    assert_eq!(AmlField::Text(String::from("OXP-1")).text(), "OXP-1");
    assert_eq!(AmlField::Int(42).int(), Some(42));
    assert_eq!(AmlField::Text(String::from("x")).int(), None);
}

#[test]
fn named_packages_are_read_without_invoking_them_as_methods() {
    let mut context = AmlContext::new(Box::new(super::super::aml_handler::FirmwareHandler),
                                      aml::DebugVerbosity::None);
    let scope = AmlName::from_str("\\CPU0").expect("scope");
    context.namespace.add_level(scope.clone(), aml::LevelType::Processor).expect("scope level");
    let pss = AmlName::from_str("_PSS").expect("name").resolve(&scope).expect("PSS path");
    context.namespace.add_value(pss, AmlValue::Package(alloc::vec![AmlValue::Package(alloc::vec![
        AmlValue::Integer(2400), AmlValue::Integer(41),
    ])])).expect("PSS value");
    let value = eval(&mut context, "\\CPU0", "_PSS").expect("named package");
    assert_eq!(package_rows(&context, &value), Some(alloc::vec![alloc::vec![
        AmlField::Int(2400), AmlField::Int(41),
    ]]));
}

#[test]
fn prw_decodes_named_gpe_device_state_and_power_resources() {
    let mut context = AmlContext::new(Box::new(super::super::aml_handler::FirmwareHandler),
                                      aml::DebugVerbosity::None);
    for (path, typ) in [("\\LID0", aml::LevelType::Device),
                        ("\\GPD0", aml::LevelType::Device),
                        ("\\PR00", aml::LevelType::PowerResource)] {
        context.namespace.add_level(AmlName::from_str(path).unwrap(), typ).unwrap();
    }
    let value = AmlValue::Package(alloc::vec![
        AmlValue::Package(alloc::vec![AmlValue::Reference(AmlName::from_str("\\GPD0").unwrap()),
            AmlValue::Integer(42)]),
        AmlValue::Integer(5),
        AmlValue::Reference(AmlName::from_str("\\PR00").unwrap()),
    ]);
    assert_eq!(decode_prw(&context, &AmlName::from_str("\\LID0").unwrap(), value, true),
        Some(PrwDevice { path: String::from("\\LID0"),
            gpe_device: Some(String::from("\\GPD0")), gpe_number: 42,
            sleep_state: 4, default_enabled: true,
            power_resources: alloc::vec![String::from("\\PR00")] }));
}

#[test]
fn prw_integer_form_selects_the_fadt_gpe_blocks() {
    let context = AmlContext::new(Box::new(super::super::aml_handler::FirmwareHandler),
                                  aml::DebugVerbosity::None);
    let scope = AmlName::from_str("\\DEV0").unwrap();
    let value = AmlValue::Package(alloc::vec![AmlValue::Integer(7), AmlValue::Integer(3)]);
    assert_eq!(decode_prw(&context, &scope, value, false),
        Some(PrwDevice { path: String::from("\\DEV0"), gpe_device: None,
            gpe_number: 7, sleep_state: 3, default_enabled: false,
            power_resources: Vec::new() }));
}

#[test]
fn malformed_prw_values_are_not_wake_sources() {
    let context = AmlContext::new(Box::new(super::super::aml_handler::FirmwareHandler),
                                  aml::DebugVerbosity::None);
    let scope = AmlName::from_str("\\DEV0").unwrap();
    for value in [
        AmlValue::Package(alloc::vec![AmlValue::Integer(7)]),
        AmlValue::Package(alloc::vec![AmlValue::Integer(256), AmlValue::Integer(3)]),
        AmlValue::Package(alloc::vec![AmlValue::Integer(7), AmlValue::Integer(6)]),
    ] {
        assert_eq!(decode_prw(&context, &scope, value, false), None);
    }
}

#[test]
fn power_resource_metadata_keeps_aml_namespace_identity() {
    let mut context = AmlContext::new(Box::new(super::super::aml_handler::FirmwareHandler),
                                      aml::DebugVerbosity::None);
    let path = AmlName::from_str("\\PR00").unwrap();
    context.namespace.add_level(path.clone(), aml::LevelType::PowerResource).unwrap();
    context.namespace.add_value(path.clone(), AmlValue::PowerResource {
        system_level: 3, resource_order: 17,
    }).unwrap();
    let value = context.namespace.get_by_path(&path).unwrap();
    assert!(matches!(value, AmlValue::PowerResource {
        system_level: 3, resource_order: 17,
    }));
}
