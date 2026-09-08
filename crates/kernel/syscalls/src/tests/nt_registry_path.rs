//! Which hive an NT key path selects, and how a path that selects none fails.

use super::*;

const STATUS_OBJECT_NAME_NOT_FOUND: u64 = 0xc000_0034;
const STATUS_OBJECT_NAME_INVALID: u64 = 0xc000_0033;
const STATUS_OBJECT_PATH_NOT_FOUND: u64 = 0xc000_003a;
const STATUS_OBJECT_PATH_SYNTAX_BAD: u64 = 0xc000_003b;

#[test]
fn the_machine_hive_keeps_the_path_beneath_it_spelled_as_asked() {
    assert_eq!(classify_absolute("\\Registry\\Machine\\System\\CurrentControlSet\\Control\\Session Manager"),
        Ok((ROOT_MACHINE, "System\\CurrentControlSet\\Control\\Session Manager".into())));
    assert_eq!(classify_absolute("\\REGISTRY\\MACHINE\\Software\\Oxide"), Ok((ROOT_MACHINE, "Software\\Oxide".into())));
    assert_eq!(classify_absolute("\\Registry\\Machine"), Ok((ROOT_MACHINE, String::new())));
}

#[test]
fn the_class_registrations_are_one_hive_under_either_spelling() {
    assert_eq!(classify_absolute("\\Registry\\Machine\\Software\\Classes"), Ok((ROOT_CLASSES, String::new())));
    assert_eq!(classify_absolute("\\Registry\\Machine\\SOFTWARE\\CLASSES\\.txt"), Ok((ROOT_CLASSES, ".txt".into())));
    // A key whose name merely begins with the same letters is not that hive.
    assert_eq!(classify_absolute("\\Registry\\Machine\\Software\\ClassesOfIts Own"),
        Ok((ROOT_MACHINE, "Software\\ClassesOfIts Own".into())));
}

#[test]
fn the_component_after_the_user_hive_selects_the_user_and_is_not_part_of_the_path() {
    // The runtime opens the current user's hive by its security identifier;
    // treating that identifier as a subkey name would put every per-user
    // setting one level too deep, where nothing would ever read it back.
    assert_eq!(classify_absolute("\\Registry\\User\\S-1-5-21-1004336348-1177238915-682003330-512\\Control Panel\\Desktop"),
        Ok((ROOT_CURRENT_USER, "Control Panel\\Desktop".into())));
    assert_eq!(classify_absolute("\\Registry\\User\\.Default\\Environment"), Ok((ROOT_CURRENT_USER, "Environment".into())));
    assert_eq!(classify_absolute("\\Registry\\User\\Current"), Ok((ROOT_CURRENT_USER, String::new())));
    assert_eq!(classify_absolute("\\Registry\\User\\S-1-5-18"), Ok((ROOT_CURRENT_USER, String::new())));
    assert_eq!(classify_absolute("\\Registry\\User"), Ok((ROOT_CURRENT_USER, String::new())));
}

#[test]
fn an_unknown_component_is_a_missing_path_only_while_more_path_follows_it() {
    assert_eq!(classify_absolute("\\Registry\\Nowhere\\Deeper"), Err(STATUS_OBJECT_PATH_NOT_FOUND));
    assert_eq!(classify_absolute("\\Registry\\Nowhere"), Err(STATUS_OBJECT_NAME_NOT_FOUND));
    assert_eq!(classify_absolute("\\Elsewhere\\Deeper"), Err(STATUS_OBJECT_PATH_NOT_FOUND));
    assert_eq!(classify_absolute("\\Elsewhere"), Err(STATUS_OBJECT_NAME_NOT_FOUND));
    assert_eq!(classify_absolute("\\Registry"), Err(STATUS_OBJECT_NAME_NOT_FOUND));
}

#[test]
fn an_absolute_path_must_begin_at_the_namespace_root() {
    assert_eq!(classify_absolute("Registry\\Machine"), Err(STATUS_OBJECT_PATH_SYNTAX_BAD));
    assert_eq!(classify_absolute(""), Err(STATUS_OBJECT_PATH_SYNTAX_BAD));
}

#[test]
fn a_relative_path_must_not_restate_the_root_it_is_already_inside() {
    assert_eq!(classify_relative("\\Registry\\Machine"), Err(STATUS_OBJECT_PATH_SYNTAX_BAD));
    assert_eq!(classify_relative("Control Panel\\Desktop"), Ok("Control Panel\\Desktop".into()));
    assert_eq!(classify_relative(""), Ok(String::new()));
}

#[test]
fn a_doubled_separator_names_nothing_at_all() {
    assert_eq!(classify_absolute("\\Registry\\Machine\\Software\\\\Oxide"), Err(STATUS_OBJECT_NAME_INVALID));
    assert_eq!(classify_relative("Software\\\\Oxide"), Err(STATUS_OBJECT_NAME_INVALID));
    // A trailing separator leaves an empty last component, which the caller
    // is free to write: only an empty component with more path after it is
    // an invalid name.
    assert_eq!(classify_relative("Software\\"), Ok("Software\\".into()));
}
