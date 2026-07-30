// Test manifest:
// - `drm_contract`: DRM object and format contract fixtures.
// - `model_parent`: driver-model ownership and canonical path fixtures.
// - `registry`: multi-device install, lookup, and teardown fixtures.
// - `support`: shared test constructors and serialization lock.
// - `wire`: virtio-gpu wire layout, encoding, and parser fixtures.

mod drm_contract;
mod model_parent;
mod registry;
mod support;
mod wire;
