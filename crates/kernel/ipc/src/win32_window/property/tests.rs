use super::*;

#[test]
fn string_set_interns_and_lookup_does_not_create() {
    let mut atoms = UserAtomTable::new();
    let atom = atoms.property_atom_for_set(&[b'T' as u16, b'e' as u16, b's' as u16, b't' as u16]).unwrap();
    assert_eq!(atoms.property_atom_for_lookup(&[b't' as u16, b'E' as u16, b'S' as u16, b'T' as u16]), Some(atom));
    assert_eq!(atoms.property_atom_for_lookup(&[b'X' as u16]), None);
}

#[test]
fn property_replacement_and_removal_return_canonical_values() {
    let mut properties = WindowProperties::new();
    properties.set(7, PropertyOrigin::String, 0x11).unwrap();
    properties.set(7, PropertyOrigin::Atom, 0x22).unwrap();
    assert_eq!(properties.get(7), Some(0x22));
    assert_eq!(properties.remove(7), Some(WindowProperty { atom: 7, origin: PropertyOrigin::Atom, value: 0x22 }));
    assert_eq!(properties.remove(7), None);
}

#[test]
fn malformed_names_are_rejected_without_atom_creation() {
    let mut atoms = UserAtomTable::new();
    assert_eq!(atoms.property_atom_for_set(&[]), None);
    assert_eq!(atoms.property_atom_for_set(&[0; MAX_PROPERTY_NAME + 1]), None);
}

#[test]
fn window_manager_property_boundary_replaces_and_destroys_canonically() {
    let mut manager = WindowManager::new();
    let window = manager.create(7, None, 0).unwrap();
    assert_eq!(manager.set_property(window, 11, PropertyOrigin::String, 0x11).unwrap(), None);
    assert_eq!(manager.set_property(window, 11, PropertyOrigin::Atom, 0x22).unwrap(), Some(WindowProperty { atom: 11, origin: PropertyOrigin::String, value: 0x11 }));
    assert_eq!(manager.get_property(window, 11).unwrap(), Some(0x22));
    assert_eq!(manager.property_atoms(window).unwrap(), Vec::<u16>::new());
    assert_eq!(manager.get_property(WindowId::from_raw(999).unwrap(), 11), Err(WindowError::NoSuchWindow));
    manager.destroy(window).unwrap();
    assert_eq!(manager.get_property(window, 11), Err(WindowError::NoSuchWindow));
}

#[test]
fn destroying_subtree_returns_each_string_atom_reference_for_release() {
    let mut manager = WindowManager::new();
    let parent = manager.create(7, None, 0).unwrap();
    let child = manager.create(7, Some(parent), 0).unwrap();
    manager.set_property(parent, 21, PropertyOrigin::String, 1).unwrap();
    manager.set_property(child, 22, PropertyOrigin::String, 2).unwrap();
    let (_, atoms) = manager.destroy_with_property_atoms(parent).unwrap();
    assert_eq!(atoms.len(), 2);
    assert_eq!(manager.get_property(child, 22), Err(WindowError::NoSuchWindow));
}

#[test]
fn property_atom_references_release_without_releasing_permanent_atoms() {
    let mut atoms = UserAtomTable::new();
    let property = atoms.property_atom_for_set(&[b'p' as u16]).unwrap();
    assert_eq!(atoms.property_atom_for_set(&[b'P' as u16]), Some(property));
    atoms.release_property_atom(property);
    assert_eq!(atoms.property_atom_for_lookup(&[b'p' as u16]), Some(property));
    atoms.release_property_atom(property);
    assert_eq!(atoms.property_atom_for_lookup(&[b'p' as u16]), None);
    let shared = atoms.property_atom_for_set(&[b's' as u16]).unwrap();
    assert_eq!(atoms.register(&[b'S' as u16]), Some(shared));
    atoms.release_property_atom(shared);
    assert_eq!(atoms.property_atom_for_lookup(&[b's' as u16]), Some(shared));
    let permanent = atoms.register(&[b'm' as u16]).unwrap();
    atoms.property_atom_for_set(&[b'm' as u16]);
    atoms.release_property_atom(permanent);
    assert_eq!(atoms.property_atom_for_lookup(&[b'm' as u16]), Some(permanent));
}

#[test]
fn atom_release_tombstones_without_retargeting_following_live_slots() {
    let mut atoms = UserAtomTable::new();
    let a = atoms.property_atom_for_set(&[b'a' as u16]).unwrap();
    let b = atoms.property_atom_for_set(&[b'b' as u16]).unwrap();
    let c = atoms.property_atom_for_set(&[b'c' as u16]).unwrap();
    atoms.release_property_atom(a);
    assert_eq!(atoms.property_atom_for_lookup(&[b'b' as u16]), Some(b));
    assert_eq!(atoms.property_atom_for_lookup(&[b'c' as u16]), Some(c));
    let reused = atoms.property_atom_for_set(&[b'd' as u16]).unwrap();
    assert_eq!(reused, a);
    assert_eq!(atoms.property_atom_for_lookup(&[b'b' as u16]), Some(b));
    assert_eq!(atoms.property_atom_for_lookup(&[b'c' as u16]), Some(c));
}
