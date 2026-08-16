//! The ioctl surface: the commands a caller can send this filesystem, what
//! their arguments mean, who may send them, and what carrying them out does.
//!
//! Split so the parts that DECIDE are pure functions of stated facts and the
//! part that acts is the only one that needs a volume. Every decision — which
//! commands exist, how far the argument travels, what the bytes mean, which
//! refusal comes first — is therefore exercised without a medium, a
//! descriptor or a caller, which is what makes the error ORDERING testable at
//! all. Order is contract here: a caller with no capability sending a
//! malformed argument branches on which of the two it is told about.
//!
//! Module manifest:
//! - `uapi`:   the command numbers, argument layouts and flag words.
//! - `spec`:   which commands exist, which stage owns each, and how far the
//!             argument travels in which direction.
//! - `arg`:    reading and writing the fixed argument structures.
//! - `policy`: the encryption policy in the form the ioctl carries it.
//! - `req`:    one decoded request per command.
//! - `perm`:   who may issue each command, and in what order refusals happen.
//! - `facts`:  the volume and file facts the ladder reads.
//! - `exec`:   carrying out an admitted request against a volume.
//! - `reply`:  what a command hands back, through which of three channels.
//! - `vol`:    the volume operations this surface is the only caller of.
//! - `fileattr`: the flag view the generic stage asks this filesystem for.
//! - `entry`:  the one call the layer above makes, start to finish.
//! - `vfs`:    the bodies behind the operations vector's ioctl entry points.

pub mod uapi;
pub mod spec;
pub mod arg;
pub mod policy;
pub mod req;
pub mod perm;
pub mod facts;
pub mod exec;
pub mod reply;
pub mod vol;
pub mod fileattr;
pub mod entry;
pub mod vfs;

pub use entry::{handle, Answer};
pub use exec::{Outcome, Unbuilt};
pub use perm::{Ctx, FileFacts, VolFacts};
pub use reply::Reply;
pub use req::{Extra, Req};
pub use spec::{owns, spec, Indirect, Payload, Spec, Stage};
