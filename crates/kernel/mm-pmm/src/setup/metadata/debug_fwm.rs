/// Count live address spaces other than `exclude_root` that still map `va` to
/// `pa`; the diagnostic free-while-mapped backstop owns this expensive walk.
/// # C: O(N_tasks)
pub fn fwm_peer_maps(va: u64, pa: u64, exclude_root: u64, hhdm: u64) -> usize {
    let target = pa & !(hal::PAGE_SIZE_BYTES - 1);
    let tasks = match sched::registry::try_snapshot() { Some(t) => t, None => return 0 };
    let mut count = 0usize;
    let mut seen: [u64; 96] = [0; 96];
    let mut n_seen = 0usize;
    for t in tasks.iter() {
        // SAFETY: debug detector reads peer roots while the task registry holds each Arc.
        let root = match unsafe { t.mm_ref() } { Some(mm) => mm.root_pa(), None => continue };
        if root == exclude_root || root == 0 || seen[..n_seen].contains(&root) { continue; }
        if n_seen < seen.len() { seen[n_seen] = root; n_seen += 1; }
        // SAFETY: HHDM covers the live foreign page-table tree; this is read-only.
        #[cfg(target_arch = "x86_64")]
        let tr = unsafe { hal::pt_walker::translate_4k_at_root::<hal_x86_64::vmm::PtWalkerX86>(root, va, hhdm) };
        // SAFETY: HHDM covers the live foreign page-table tree; this is read-only.
        #[cfg(target_arch = "aarch64")]
        let tr = unsafe { hal::pt_walker::translate_4k_at_root::<hal_aarch64::vmm::PtWalkerArm>(root, va, hhdm) };
        if tr.is_some_and(|(mapped, _)| (mapped & !(hal::PAGE_SIZE_BYTES - 1)) == target) { count += 1; }
    }
    count
}
