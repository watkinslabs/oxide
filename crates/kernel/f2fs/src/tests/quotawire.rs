//! Allocations are charged to the identities that own them.
//!
//! The quota decode, tree walk and limit decision have tests of their own.
//! These are about the CALL SITES: whether a write charges anything, whether
//! a limit refuses anything, and whether what was charged survives.
//!
//! Module manifest:
//! - `fixture`: the volumes, images and records the tests below are built on.
//! - `charge`:  what a write, a create and a delete charge and give back.
//! - `records`: identities the file has never held, and files the mount names.
//! - `release`: space returned when an attribute or a directory block goes.
//! - `project`: what a project's own tree reports as free.
//!
//! Every child is declared with an explicit path: a bare `mod x;` in a module
//! loaded by path binds against the parent directory and would silently
//! compile a sibling of the same name.

use super::*;
use crate::mode::S_IFREG;
use crate::opts::Options;
use crate::quota::info::Revision;
use crate::quota::uapi::QT_BLOCK_SIZE;
use crate::test_image::quota_image as qi;
use crate::test_image::{self, nodes, ROOT_INO};
use crate::volume::quotas::USRQUOTA;
use crate::volume::{NewInode, Volume};
use alloc::vec;
use alloc::vec::Vec;
use sectors::MemImage;

#[path = "quotawire/fixture.rs"] mod fixture;
#[path = "quotawire/charge.rs"] mod charge;
#[path = "quotawire/records.rs"] mod records;
#[path = "quotawire/release.rs"] mod release;
#[path = "quotawire/project.rs"] mod project;
