// userfaultfd(2) decision logic — every validation ladder, errno choice and
// reply bitmap, as pure functions over plain scalars.
//
// UNGATED on purpose (`docs/53` + the phantom-test rule in CLAUDE.md): the
// ioctl bodies and the fault path are `target_os = "oxide-kernel"`, so a
// `#[cfg(test)]` block inside them never compiles. Keeping the decisions here
// is what makes `tests/policy*.rs` a real gate.
//
// Module manifest:
//   - range: the two range validators every op starts from.
//   - create: fd creation, the API handshake, ioctl ordering, fault delivery.
//   - register: registration modes, the per-VMA ladder, the ioctls reply.
//   - fill: the COPY/ZEROPAGE/CONTINUE/POISON destination ladder and the
//     shared short-fill return protocol.
//   - wp: the WRITEPROTECT mode word and per-VMA ladder.
//   - movepg: the MOVE mode word and the two-VMA compatibility ladder.
//   - events: the cooperative address-space events and the in-flight-change
//     refusal every resolve runs first.

pub mod range;
pub mod create;
pub mod register;
pub mod fill;
pub mod wp;
pub mod movepg;
pub mod events;

pub use range::{validate_range, validate_unaligned_range};
pub use create::{api_negotiate, check_create, check_ioctl_ordering, is_initialized,
                 may_deliver_fault, syscall_allowed, wp_async, wp_unpopulated, ApiReply};
pub use register::{check_register_mode, check_register_vma, modes_of, register_ioctls,
                   vma_can_userfault, RegVma};
pub use fill::{check_copy_mode, check_continue_mode, check_dst_vma, check_poison_mode,
               check_zeropage_mode, fill_retval, should_wake, DstVma, FillKind};
pub use wp::{check_wp_mode, check_wp_vma, wp_use_markers, WpMode, WpVma};
pub use movepg::{check_move_areas, check_move_mode, check_move_ranges, MoveMode, MoveVma};
pub use events::{check_mmap_changing, event_feature, event_msg, next_message, wants_event,
                 NextMessage};
