// Send-path test manifest.
// - `common`: target builders, control encoders, phase-recording `MessageIo`.
// - `batch`: `sendmmsg` per-entry division and the Linux entry cap.
// - `phases`: single-message ordering and target classification.
// - `vsock`: AF_VSOCK destination and transport answers.
// - `unix_scm`: AF_UNIX SCM_RIGHTS pinning across payload failure and fd reuse.

mod common;
mod batch;
mod phases;
mod vsock;
mod unix_scm;
