/// Shared-aware snapshot already releases owner locks before this DWORD copy. # C: O(processes + DCs + fonts)
pub(crate) fn route(ordinal:u64,args:&[u64])->Option<u64> {
    super::route(ordinal,args,|dc|crate::nt_gdi::text_snapshot_for_current(dc).ok().map(|state|state.attributes),
        crate::nt_gdi::dc_query_value,|pointer,value|uaccess::put_user_u32(pointer,value).is_ok())
}
