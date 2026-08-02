// Hosted coverage of the core-file layout. Module manifest:
//   fixture   inputs the cases are built from
//   reader    an independent parser the cases read the output back through
//   header    ELF header fields and the program-header table's shape
//   notes     note padding, order, and the two identity structures' offsets
//   files     the `NT_FILE` mapping table
//   segments  `PT_LOAD` offsets, flags, elision, and memory holes
//   xnum      the extended-numbering escape
//   consistency  every published offset checked against where bytes landed

pub(crate) mod fixture;
pub(crate) mod reader;

mod header;
mod notes;
mod files;
mod segments;
mod xnum;
mod consistency;
