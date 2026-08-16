// Test manifest: one file per contract.
//   support  — fake lower interface and attribute/frame builders
//   tci      — tag encode/decode and the insert/strip round trip
//   prio     — the two priority tables
//   caps     — lower-interface derived rules
//   xmit     — tag placement decisions and the frames they produce
//   dev      — interface transmit and receive behaviour
//   registry — tag claiming and receive-side demultiplex
//   netlink  — attribute parse, validation errnos, creation and change

mod support;
mod tci;
mod prio;
mod caps;
mod xmit;
mod dev;
mod registry;
mod netlink;
mod link_kind;
