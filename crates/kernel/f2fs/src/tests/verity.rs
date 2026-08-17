//! Verity metadata, read out of records built byte by byte from the format.
//!
//! Module manifest:
//! - `image`: the two records, assembled by hand.
//! - `size`:  where the data stops and the metadata starts.
//! - `desc`:  the descriptor, its tree, and what may be done to the file.

#[path = "verity/image.rs"] mod image;
#[path = "verity/size.rs"] mod size;
#[path = "verity/desc.rs"] mod desc;
