/// # C: O(processes + regions)
pub(crate) fn route(ordinal:u64,args:&[u64])->Option<u64>{
    super::route(ordinal,args,crate::nt_gdi::set_rect_region_for_current)
}
