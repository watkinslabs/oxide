use super::*;
use alloc::vec;

use crate::hibernate::format::{self, Header, Page};
use crate::hibernate::image::{self, Plan};

struct Store { pages: Vec<Page> }
impl image::Storage for Store {
    type Error = ();
    fn page_count(&self) -> u64 { self.pages.len() as u64 }
    fn read_page(&mut self, page: u64, out: &mut Page) -> Result<(), ()> {
        *out = *self.pages.get(page as usize).ok_or(())?; Ok(())
    }
    fn write_page(&mut self, page: u64, data: &Page) -> Result<(), ()> {
        *self.pages.get_mut(page as usize).ok_or(())? = *data; Ok(())
    }
    fn flush(&mut self) -> Result<(), ()> { Ok(()) }
    fn commit_page(&mut self, page: u64, data: &Page) -> Result<(), ()> {
        self.write_page(page, data)
    }
}

#[derive(Debug)]
struct Frame { pfn: u64, data: Page }
struct Mem { exact: Vec<u64>, safe: Vec<u64>, allocations: usize }
impl Memory for Mem {
    type Frame = Frame;
    fn topology(&self) -> &[super::super::snapshot::Region] {
        static TOPOLOGY: [super::super::snapshot::Region; 1] = [super::super::snapshot::Region {
            start_pfn: 0, end_pfn: 64, kind: super::super::snapshot::MemoryKind::Usable,
        }];
        &TOPOLOGY
    }
    fn claim_exact(&mut self, pfn: u64) -> Option<Frame> {
        self.exact.contains(&pfn).then(|| { self.allocations += 1; Frame { pfn, data: [0; format::PAGE_SIZE] } })
    }
    fn alloc_safe(&mut self) -> KResult<Frame> {
        self.allocations += 1;
        if self.safe.is_empty() { return Err(Error::Nomem); }
        let pfn = self.safe.remove(0);
        Ok(Frame { pfn, data: [0; format::PAGE_SIZE] })
    }
    fn frame_pfn(&self, frame: &Frame) -> u64 { frame.pfn }
    fn write(&self, frame: &mut Frame, page: &Page) { frame.data = *page; }
    fn zero(&self, frame: &mut Frame) { frame.data = [0; format::PAGE_SIZE]; }
}

fn header(image_pages: u64, zero_pages: u64) -> Header {
    Header { flags: format::FLAG_NOCOMPRESS | format::FLAG_CRC32, checksum: 0,
        first_map: 0, image_pages, zero_pages, stream_pages: 0, arch: 1,
        cpu_count: 1, hardware_sig: 0, build_id: [1; 32], topology_id: [2; 32],
        cpu_id: [3; 32], arch_data: [4; 128], original_sig: [0; 10] }
}

fn compatibility() -> Compatibility {
    Compatibility { arch: 1, cpu_count: 1, hardware_sig: 0, build_id: [1; 32],
        topology_id: [2; 32], cpu_id: [3; 32] }
}

fn admitted(reader: &ImageReader) -> Admission<'_> {
    admit(reader, &compatibility(), |_| Ok(())).unwrap()
}

fn store_with_pfns(pfns: &[u64]) -> (Store, ImageReader) {
    let copied = 1;
    let zero = pfns.len() - copied;
    let info = stream::layout(copied as u64, zero as u64).unwrap();
    let mut info_page = [0; format::PAGE_SIZE];
    stream::encode_info_into(info, &mut info_page).unwrap();
    let mut pfn_page = [0; format::PAGE_SIZE];
    stream::encode_pfn_page_into(info, 0, &mut pfn_page,
        |index| pfns.get(index).copied()).unwrap();
    let logical = [info_page, pfn_page, [0x5a; format::PAGE_SIZE]];
    let mut store = Store { pages: vec![[0; format::PAGE_SIZE]; 8] };
    store.pages[0][format::OFF_SIG..].copy_from_slice(&format::SWAP_SIG_NEW);
    image::write_image(&mut store,
        &Plan { header_page: 0, map_pages: &[1], data_pages: &[2, 3, 4] },
        header(pfns.len() as u64, zero as u64), &logical).unwrap();
    let reader = ImageReader::open(&mut store, 0).unwrap();
    (store, reader)
}

#[test]
fn exact_destination_and_safe_collision_share_one_restore_owner() {
    let (mut store, reader) = store_with_pfns(&[2, 3]);
    let mut memory = Mem { exact: vec![2], safe: vec![20], allocations: 0 };
    let image = load(admitted(&reader), &mut store, &mut memory).unwrap();
    assert_eq!(image.copied()[0].original_pfn, 2);
    assert_eq!(image.copied()[0].source_pfn, 2);
    assert_eq!(image.copied()[0].frame.data, [0x5a; format::PAGE_SIZE]);
    assert_eq!(image.zero()[0].original_pfn, 3);
    assert_eq!(image.zero()[0].source_pfn, 20);
    assert_eq!(image.collision_count(), 1);
}

#[test]
fn duplicate_destination_is_rejected_before_any_frame_claim() {
    let (mut store, reader) = store_with_pfns(&[2, 2]);
    let mut memory = Mem { exact: vec![2], safe: vec![20], allocations: 0 };
    assert!(matches!(load(admitted(&reader), &mut store, &mut memory), Err(Error::Inval)));
    assert_eq!(memory.allocations, 0);
}

#[test]
fn checksum_corruption_is_invalid_before_any_frame_claim() {
    let (mut store, reader) = store_with_pfns(&[2, 3]);
    store.pages[4][0] ^= 1;
    let mut memory = Mem { exact: vec![2], safe: vec![20], allocations: 0 };
    assert_eq!(load(admitted(&reader), &mut store, &mut memory).err(), Some(Error::Inval));
    assert_eq!(memory.allocations, 0);
}

#[test]
fn every_compatibility_identity_mismatch_is_rejected() {
    let expected = compatibility();
    let base = header(2, 1);
    assert_eq!(validate_compatibility(&base, &expected), Ok(()));
    let mutations: [fn(&mut Header); 6] = [
        |h| h.arch ^= 1,
        |h| h.cpu_count += 1,
        |h| h.hardware_sig ^= 1,
        |h| h.build_id[0] ^= 1,
        |h| h.topology_id[0] ^= 1,
        |h| h.cpu_id[0] ^= 1,
    ];
    for mutate in mutations {
        let mut changed = base.clone();
        mutate(&mut changed);
        assert_eq!(validate_compatibility(&changed, &expected), Err(Error::Inval));
    }
}

#[test]
fn architecture_rejection_precedes_every_destination_claim() {
    let (_store, mut reader) = store_with_pfns(&[2, 3]);
    let memory = Mem { exact: vec![2], safe: vec![20], allocations: 0 };
    reader.header.arch_data[0] ^= 1;
    let admission = admit(&reader, &compatibility(), |arch_data|
        if arch_data[0] == 4 { Ok(()) } else { Err(Error::Inval) });
    assert!(matches!(admission, Err(Error::Inval)));
    assert_eq!(memory.allocations, 0);
}

#[test]
fn safe_restore_consumes_image_and_pins_one_owner_for_every_safe_page() {
    let (mut store, reader) = store_with_pfns(&[2, 3]);
    let mut memory = Mem { exact: vec![2], safe: vec![20, 30, 31, 32], allocations: 0 };
    let image = load(admitted(&reader), &mut store, &mut memory).unwrap();
    let plan = prepare_safe(image, &mut memory, 3).unwrap();
    assert_eq!(plan.collision_count(), 1);
    assert_eq!(plan.collision(0), Some(Collision { source_pfn: 20, destination_pfn: 3 }));
    assert_eq!(plan.physical_collision(0).unwrap(), PhysicalCollision {
        source_pa: 20 * format::PAGE_SIZE as u64,
        destination_pa: 3 * format::PAGE_SIZE as u64 });
    assert_eq!(plan.x86_collision(0).unwrap(), hal_x86_64::hibernate::Collision {
        source_pa: 20 * format::PAGE_SIZE as u64,
        destination_pa: 3 * format::PAGE_SIZE as u64 });
    assert_eq!(plan.arm_collision(0).unwrap(), hal_aarch64::hibernate::Collision {
        source_pa: 20 * format::PAGE_SIZE as u64,
        destination_pa: 3 * format::PAGE_SIZE as u64 });
    assert_eq!(plan.control_count(), 3);
    assert_eq!(plan.control_pfn(0), Some(30));
    assert_eq!(plan.control_pfn(2), Some(32));
    assert_eq!(plan.safe_page_count(), 4);
    assert_eq!(plan.safe_pa(3).unwrap(), 32 * format::PAGE_SIZE as u64);
    assert_eq!((0..plan.safe_page_count()).map(|i| plan.safe_pfn(i).unwrap()).collect::<Vec<_>>(),
        [20, 30, 31, 32]);
    assert_eq!(plan.physical_span(), Some(PfnRange { start: 2, end: 33 }));
    assert_eq!(plan.physical_span_bytes().unwrap(), PhysicalRange {
        start: 2 * format::PAGE_SIZE as u64, end: 33 * format::PAGE_SIZE as u64 });
    assert_eq!(plan.x86_direct_map().unwrap(), hal_x86_64::hibernate::PhysRange {
        start: 2 * format::PAGE_SIZE as u64, end: 33 * format::PAGE_SIZE as u64 });
    assert_eq!(plan.arm_physical_map().unwrap(), hal_aarch64::hibernate::PhysRange {
        start: 2 * format::PAGE_SIZE as u64, end: 33 * format::PAGE_SIZE as u64 });
    assert_eq!(plan.copied()[0].frame.data, [0x5a; format::PAGE_SIZE]);
    assert_eq!(plan.zero()[0].frame.data, [0; format::PAGE_SIZE]);
}

#[test]
fn every_safe_frame_allocation_failure_aborts_before_terminal_plan() {
    // One collision frame is needed by load, then three control frames by
    // prepare_safe.  Exercise every prefix so each allocation seam is a
    // deterministic positive control for the no-partial-plan contract.
    for available in 0..4 {
        let (mut store, reader) = store_with_pfns(&[2, 3]);
        let mut memory = Mem { exact: vec![2], safe: (20..20 + available as u64).collect(),
            allocations: 0 };
        match load(admitted(&reader), &mut store, &mut memory) {
            Err(error) => assert_eq!(error, Error::Nomem),
            Ok(image) => assert_eq!(prepare_safe(image, &mut memory, 3).err(), Some(Error::Nomem)),
        }
        assert_eq!(memory.allocations, available + 2,
            "one exact claim plus every available/failed safe allocation must be observed");
    }
    let (mut store, reader) = store_with_pfns(&[2, 3]);
    let mut memory = Mem { exact: vec![2], safe: vec![20, 21, 22, 23], allocations: 0 };
    let image = load(admitted(&reader), &mut store, &mut memory).unwrap();
    assert!(prepare_safe(image, &mut memory, 3).is_ok(),
        "positive control must reach a complete safe plan with all four frames");
}

#[test]
fn duplicate_safe_source_is_rejected_during_load() {
    let (mut store, reader) = store_with_pfns(&[2, 3, 4]);
    let mut memory = Mem { exact: vec![2], safe: vec![20, 20], allocations: 0 };
    assert!(matches!(load(admitted(&reader), &mut store, &mut memory), Err(Error::Inval)));
}

#[test]
fn every_destination_can_collide_with_linear_indexed_plan() {
    let (mut store, reader) = store_with_pfns(&[2, 3, 4, 5]);
    let mut memory = Mem { exact: vec![], safe: vec![20, 21, 22, 23, 30], allocations: 0 };
    let image = load(admitted(&reader), &mut store, &mut memory).unwrap();
    assert_eq!(image.collision_count(), 4);
    assert_eq!(memory.allocations, 4);
    let mut restore = prepare_safe(image, &mut memory, 0).unwrap();
    assert_eq!(memory.allocations, 4, "terminal plan construction with no controls must not allocate");
    assert_eq!((0..restore.collision_count()).map(|index| restore.collision(index).unwrap())
        .collect::<Vec<_>>(), [
            Collision { source_pfn: 20, destination_pfn: 2 },
            Collision { source_pfn: 21, destination_pfn: 3 },
            Collision { source_pfn: 22, destination_pfn: 4 },
            Collision { source_pfn: 23, destination_pfn: 5 },
        ]);
    restore.prepare_collision_chain(&mut memory).unwrap();
    assert_eq!(restore.collision_node_count(), 1);
}

#[test]
fn destination_outside_canonical_topology_is_rejected_before_claim() {
    let (mut store, reader) = store_with_pfns(&[2, 64]);
    let mut memory = Mem { exact: vec![2], safe: vec![20], allocations: 0 };
    assert_eq!(load(admitted(&reader), &mut store, &mut memory).err(), Some(Error::Inval));
    assert_eq!(memory.allocations, 0);
}

#[test]
fn control_page_reusing_a_destination_is_rejected_before_plan_publication() {
    let (mut store, reader) = store_with_pfns(&[2, 3]);
    let mut memory = Mem { exact: vec![2], safe: vec![20, 2], allocations: 0 };
    let image = load(admitted(&reader), &mut store, &mut memory).unwrap();
    assert!(matches!(prepare_safe(image, &mut memory, 1), Err(Error::Inval)));
}

#[test]
fn one_owner_serializes_and_pins_the_physical_collision_chain() {
    let (mut store, reader) = store_with_pfns(&[2, 3]);
    let mut memory = Mem { exact: vec![2], safe: vec![20, 30], allocations: 0 };
    let image = load(admitted(&reader), &mut store, &mut memory).unwrap();
    let mut restore = prepare_safe(image, &mut memory, 0).unwrap();
    restore.prepare_collision_chain(&mut memory).unwrap();
    assert_eq!(restore.collision_head_pa(), 30 * format::PAGE_SIZE as u64);
    assert_eq!(restore.collision_node_count(), 1);
    assert_eq!(restore.safe_page_count(), 2);
    let node = &restore.control(0).unwrap().data;
    assert_eq!(u64::from_le_bytes(node[..8].try_into().unwrap()), 0);
    assert_eq!(u64::from_le_bytes(node[8..16].try_into().unwrap()), 1);
    assert_eq!(u64::from_le_bytes(node[16..24].try_into().unwrap()), 20 * format::PAGE_SIZE as u64);
    assert_eq!(u64::from_le_bytes(node[24..32].try_into().unwrap()), 3 * format::PAGE_SIZE as u64);
    assert_eq!(restore.prepare_collision_chain(&mut memory), Err(Error::Busy));
    assert_eq!(core::mem::size_of::<hal_x86_64::hibernate::CollisionPage>(), format::PAGE_SIZE);
    assert_eq!(core::mem::size_of::<hal_aarch64::hibernate::CollisionPage>(), format::PAGE_SIZE);
    assert_eq!(super::chain::COLLISIONS_PER_PAGE, hal_x86_64::hibernate::COLLISIONS_PER_PAGE);
    assert_eq!(super::chain::COLLISIONS_PER_PAGE, hal_aarch64::hibernate::COLLISIONS_PER_PAGE);
}
