// Hosted test manifest for userfaultfd(2).
//
//   - policy.rs: the ungated decision ladders (create gate, range validation,
//     API negotiation, register modes/VMA scan, destination-VMA ladder,
//     return protocol) against Linux `mm/userfaultfd.c`.
//   - ioctl.rs: the dispatcher end-to-end over a real `vmm::AddressSpace` —
//     including the negative case that a COPY into an unregistered or
//     unmapped destination is REFUSED before any page is installed.

mod policy;
mod ioctl;
