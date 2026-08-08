// UFFDIO_* dispatch — the ABI shim only (`docs/53`): validate the user object,
// hand the decision to `policy`, call one work function, encode the reply.
//
// Every range op targets the address space captured when the fd was created,
// NOT the caller's. The fd survives fork, exec and being passed over a socket,
// so resolving the destination against the caller would let a process that
// merely HOLDS the fd install pages into its own address space.
//
// Module manifest:
//   - structs: the request objects and the user-memory read/write helpers.
//   - dispatch: the command table.
//   - api: UFFDIO_API.
//   - register: UFFDIO_REGISTER / UNREGISTER / WAKE.
//   - fill: UFFDIO_COPY / ZEROPAGE / CONTINUE / POISON.
//   - wp: UFFDIO_WRITEPROTECT.
//   - movepg: UFFDIO_MOVE.

mod structs;
mod dispatch;
mod api;
mod register;
mod fill;
mod wp;
mod movepg;

pub use dispatch::handle_uffd_ioctl;
