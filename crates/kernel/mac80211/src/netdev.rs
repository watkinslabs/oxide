// The network-device face of a wireless interface.
//
// Module manifest:
// - `convert`:  conversion between Ethernet and 802.11 frames, both ways.
// - `dev`:      the device the network stack sees, and the delivery trait.
// - `register`: publishing an interface and installing its delivery hook.

#[path = "netdev/convert.rs"] pub mod convert;
#[path = "netdev/dev.rs"] pub mod dev;
#[path = "netdev/register.rs"] pub mod register;

pub use convert::EthFrame;
pub use dev::{RxDeliver, WirelessNetDev};
pub use register::{register, unregister};
