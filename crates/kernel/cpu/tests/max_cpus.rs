const _: [(); hal::MAX_CPUS] = [(); cpu::MAX_CPUS];
const _: [(); hal::MAX_CPUS] = [(); sync::MAX_CPUS];

#[test]
fn public_cpu_bounds_are_the_canonical_item() {
    assert_eq!(cpu::MAX_CPUS, hal::MAX_CPUS);
    assert_eq!(sync::MAX_CPUS, hal::MAX_CPUS);
}
