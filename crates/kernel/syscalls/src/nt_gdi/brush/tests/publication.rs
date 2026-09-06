use super::*;
use core::cell::Cell;

#[test]
fn creation_requires_publication_and_rolls_back_on_failure() {
    let published = Cell::new(0); let removed = Cell::new(0);
    assert_eq!(publish_created(7, |id| { published.set(id); Ok::<_, u32>(()) }, |id| { removed.set(id); Ok(()) }), Ok(7));
    assert_eq!(published.get(), 7); assert_eq!(removed.get(), 0);
    assert_eq!(publish_created(8, |_| Err(12), |id| { removed.set(id); Ok(()) }), Err(12));
    assert_eq!(removed.get(), 8);
    assert_eq!(publish_created(9, |_| Err(12), |_| Err(13)), Err(13));
}

#[test]
fn only_collected_previous_selection_loses_client_projection() {
    let cleared = Cell::new(0);
    assert_eq!(finish_selection(7, true, |id| { cleared.set(id); Ok::<_, u32>(()) }), Ok(7));
    assert_eq!(cleared.get(), 0);
    assert_eq!(finish_selection(7, false, |id| { cleared.set(id); Ok::<_, u32>(()) }), Ok(7));
    assert_eq!(cleared.get(), 7);
    assert_eq!(finish_selection(8, false, |_| Err(12)), Err(12));
}
