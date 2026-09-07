// Module manifest — hosted tests over a simulated address space.
// - `backend`   — counting `HeapBackend` fixture plus the page-per-alloc control
// - `blocks`    — block geometry: alignment, exact sizes, zeroing, large blocks
// - `churn`     — long mixed workload: bodies intact, bounded reservations
// - `mappings`  — address-space operation counts, and the control that fails
// - `coalesce`  — neighbour merging, region reuse, empty-region release
// - `resize`    — in-place shrink/grow, move-and-copy, in-place-only refusal
// - `records`   — walk order and user records

#[path = "backend.rs"] pub mod backend;
#[path = "blocks.rs"] mod blocks;
#[path = "churn.rs"] mod churn;
#[path = "coalesce.rs"] mod coalesce;
#[path = "mappings.rs"] mod mappings;
#[path = "records.rs"] mod records;
#[path = "resize.rs"] mod resize;
