use super::*;

/// A damage record names one rectangle of one window, from the display side.
#[test]
fn damage_roundtrips_one_window_rectangle_and_travels_from_the_backend() {
    assert_eq!(Opcode::decode(0x109), Ok(Opcode::Damage));
    assert!(Opcode::Damage.from_backend());
    let rect = Rect { x: -3, y: 7, width: 40, height: 25 };
    let record = Record::new(Opcode::Damage, 4, 0x2a, rect.encode().unwrap().to_vec()).unwrap();
    let bytes = record.encode().unwrap();
    let header = Header::decode(&bytes[..HEADER_LEN]).unwrap();
    assert_eq!((header.opcode, header.length, header.hwnd), (Opcode::Damage, 16, 0x2a));
    assert_eq!(Rect::decode(&bytes[HEADER_LEN..]).unwrap(), rect);
}

/// A rectangle with no area names no pixels, and damage always names a window.
#[test]
fn damage_rejects_an_empty_rectangle_a_wrong_length_and_a_missing_window() {
    for empty in [Rect { x: 0, y: 0, width: 0, height: 4 }, Rect { x: 0, y: 0, width: 4, height: 0 }] {
        let payload = Rect { x: empty.x, y: empty.y, width: empty.width, height: empty.height }.encode_window().unwrap().to_vec();
        assert_eq!(Record::new(Opcode::Damage, 4, 1, payload), Err(Error::Payload));
    }
    assert_eq!(Record::new(Opcode::Damage, 4, 1, alloc::vec![0; 12]), Err(Error::Length));
    assert_eq!(Record::new(Opcode::Damage, 4, 0, Rect { x: 0, y: 0, width: 4, height: 4 }.encode().unwrap().to_vec()), Err(Error::Payload));
    let oversized = Rect { x: 0, y: 0, width: MAX_DIMENSION + 1, height: 4 };
    let mut payload = [0u8; 16];
    for (i, value) in [oversized.x as u32, oversized.y as u32, oversized.width, oversized.height].iter().enumerate() { payload[i*4..i*4+4].copy_from_slice(&value.to_le_bytes()); }
    assert_eq!(Record::new(Opcode::Damage, 4, 1, payload.to_vec()), Err(Error::Payload));
}
