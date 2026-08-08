// Hosted test manifest for userfaultfd(2).
//
//   - policy.rs: the create gate, the API handshake, ioctl ordering, range
//     validation and the ABI numbers.
//   - modes.rs: the per-mode ladders — where each registration mode is legal,
//     what the registration promises, and how each resolve validates itself.
//   - ioctl.rs: the dispatcher end-to-end over a real `vmm::AddressSpace` —
//     including the negative cases that a fill into an unregistered or
//     unmapped destination is REFUSED before any page is installed.
//   - ioctl_modes.rs: the four mode-specific commands end-to-end — which
//     registration each demands, and what lands in its reply word.
//   - events.rs: the cooperative half — what a fork, a move and a range change
//     carry into the child / the destination / the monitor's queue, and the
//     refusal every resolve meets while one is outstanding.

mod policy;
mod modes;
mod ioctl;
mod ioctl_modes;
mod events;
