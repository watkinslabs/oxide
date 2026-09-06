/// Both ingress forms call the same typed region owner and bounded copy policy. # C: canonical region-operation cost
pub(crate) fn route(ordinal:u64,args:&[u64])->Option<u64> {
    super::route(ordinal,args,|rect|crate::nt_gdi::create_rect_region_for_current(rect).ok(),
        |handle|crate::nt_gdi::region_box_for_current(handle).ok(),crate::nt_gdi::combine_region_for_current,
        |pointer,bytes|uaccess::copy_to_user(pointer,bytes).is_ok())
}
