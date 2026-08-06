/// Cache policy carried by a raw-PFN VMA into every installed leaf.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum PhysCacheMode {
    WriteBack,
    Device,
    WriteCombine,
}
