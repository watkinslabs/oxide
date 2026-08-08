// The message-ABI layout owner: the ONE place that decides whether a socket
// message syscall speaks the native LP64 `msghdr` family or the 32-bit compat
// one, and the ONE place that knows what each of those shapes looks like.
//
// Why one owner. `MSG_CMSG_COMPAT` is not a user-settable flag: a native entry
// that sees it reports EINVAL, and a compat entry sets it itself. Those are two
// halves of a single rule, and a tree that keeps them apart gets the B1641
// shape — `sendmmsg` masked the flag off the value it handed the batch AND
// used the same flag to pick a 32-bit header decoder, so the guard that was
// supposed to be canonical could never fire while a caller still chose the
// parsed layout. Here the entry asks [`entry::layout`] once, gets a TYPED
// [`MsgLayout`] back, and every decoder is driven by that value. The flag is
// never re-read as a layout selector anywhere downstream.
//
// Module manifest:
// - `shape`: [`MsgLayout`] and every offset, stride, and width the two ABIs
//   differ in — msghdr fields, iovec, mmsghdr, cmsghdr.
// - `entry`: [`EntryAbi`] and the admission rule above.
// - `cmsg`: the ancillary-stream conversions, which are the part of the compat
//   ABI that is not a simple offset change — 32-bit control data has a
//   different header size AND a different alignment, so a compat send must be
//   rebuilt into native form before any protocol parses it, and a compat
//   receive must be emitted in 32-bit form.
//
// Ungated on purpose: the slot files are `#[cfg(target_os = "oxide-kernel")]`,
// so a decision left in one of them cannot be tested at all.

pub mod cmsg;
pub mod entry;
pub mod shape;

pub use entry::{EntryAbi, layout as entry_layout};
pub use shape::{MsgLayout, TIMESPEC_SIZE};

#[cfg(test)]
mod tests;
