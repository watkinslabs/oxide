use super::*;

#[test]
fn page_span_covers_every_intersecting_page() {
    assert_eq!(page_span(0, 1), (0, 1));
    assert_eq!(page_span(0, PG), (0, 1));
    assert_eq!(page_span(0, PG + 1), (0, 2));
    assert_eq!(page_span(PG - 1, PG + 1), (0, 2));
    assert_eq!(page_span(PG, u64::MAX), (1, u64::MAX));
    assert_eq!(page_span(3 * PG, 3 * PG), (3, 3));
}

fn lock_is_free(m: &BdevMapping) -> bool { m.st.try_lock().is_some() }

#[test]
fn a_read_hands_bytes_to_the_caller_with_the_mapping_lock_free() {
    let m = mapping_over(medium(64));
    m.write_at(0, &[0x5E; 64]).unwrap();
    let mut chunks = 0usize;
    let mut got = Vec::new();
    let n = m.read_iter(0, 64, |at, src| {
        assert_eq!(at, got.len());
        assert!(lock_is_free(&m));
        chunks += 1;
        got.extend_from_slice(src);
        Ok(())
    }).unwrap();
    assert_eq!(n, 64);
    assert_eq!(chunks, 1);
    assert_eq!(got, vec![0x5E; 64]);
}

#[test]
fn a_write_takes_bytes_from_the_caller_with_the_mapping_lock_free() {
    let m = mapping_over(medium(64));
    let mut chunks = 0usize;
    let n = m.write_iter(0, 64, |at, dst| {
        assert_eq!(at, 0);
        assert!(lock_is_free(&m));
        chunks += 1;
        dst.fill(0xC3);
        Ok(())
    }).unwrap();
    assert_eq!(n, 64);
    assert_eq!(chunks, 1);
    let mut buf = [0u8; 64];
    m.read_at(0, &mut buf).unwrap();
    assert_eq!(buf, [0xC3; 64]);
}

#[test]
fn a_multi_page_transfer_frees_the_lock_for_every_chunk() {
    let m = mapping_over(medium(64));
    m.write_at(PG - 8, &[0x1D; 16]).unwrap();
    let mut ats = Vec::new();
    m.read_iter(PG - 8, 16, |at, _| {
        assert!(lock_is_free(&m));
        ats.push(at);
        Ok(())
    }).unwrap();
    assert_eq!(ats, vec![0, 8]);
    let mut ats = Vec::new();
    m.write_iter(PG - 8, 16, |at, dst| {
        assert!(lock_is_free(&m));
        ats.push(at);
        dst.fill(0x2E);
        Ok(())
    }).unwrap();
    assert_eq!(ats, vec![0, 8]);
    let mut buf = [0u8; 16];
    m.read_at(PG - 8, &mut buf).unwrap();
    assert_eq!(buf, [0x2E; 16]);
}

#[test]
fn a_transfer_error_stops_the_request_and_is_reported() {
    let m = mapping_over(medium(64));
    assert_eq!(m.read_iter(PG - 8, 16, |at, _| if at == 0 { Ok(()) } else { Err(BlockError::Eio) }),
        Err(BlockError::Eio));
    assert_eq!(m.write_iter(0, 8, |_, _| Err(BlockError::Eio)), Err(BlockError::Eio));
    assert_eq!(m.dirty_pages(), 0);
}
