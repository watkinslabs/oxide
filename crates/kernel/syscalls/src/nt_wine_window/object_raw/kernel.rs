use super::Query;

/// Forward an admitted query without an adapter-side object registry. # C: canonical object query cost
pub(crate) fn dispatch(query: Query) -> u64 {
    crate::nt_gdi::get_object_w_for_current(query.handle, query.count, query.output)
}
