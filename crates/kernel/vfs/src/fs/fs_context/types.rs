extern crate alloc;

use alloc::string::{String, ToString};
use alloc::vec::Vec;

use crate::types::VfsError;

pub type KResult<T> = core::result::Result<T, VfsError>;

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum FsContextPurpose { Mount, Submount, Reconfigure }

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum FsContextPhase {
    CreateParams,
    Creating,
    AwaitingMount,
    AwaitingReconf,
    ReconfParams,
    Reconfiguring,
    Failed,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum FsValue {
    Flag,
    String(String),
    File(i32),
    Filename { path: String, empty: bool },
    Blob(Vec<u8>),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FsParameter {
    pub key:   String,
    pub value: FsValue,
}

impl FsParameter {
    pub fn flag(key: &str) -> Self { Self { key: key.to_string(), value: FsValue::Flag } }
    pub fn string(key: &str, value: &str) -> Self { Self { key: key.to_string(), value: FsValue::String(value.to_string()) } }
    pub fn fd(key: &str, fd: i32) -> Self { Self { key: key.to_string(), value: FsValue::File(fd) } }
    pub fn path(key: &str, path: &str) -> Self {
        Self { key: key.to_string(), value: FsValue::Filename { path: path.to_string(), empty: false } }
    }
    pub fn path_empty(key: &str, path: &str) -> Self {
        Self { key: key.to_string(), value: FsValue::Filename { path: path.to_string(), empty: true } }
    }
    pub fn blob(key: &str, blob: &[u8]) -> Self { Self { key: key.to_string(), value: FsValue::Blob(blob.to_vec()) } }
    pub fn as_str(&self) -> Option<&str> { match &self.value { FsValue::String(s) => Some(s), _ => None } }
    pub fn as_fd(&self) -> Option<i32> { match &self.value { FsValue::File(fd) => Some(*fd), _ => None } }
    pub fn as_path(&self) -> Option<(&str, bool)> {
        match &self.value { FsValue::Filename { path, empty } => Some((path, *empty)), _ => None }
    }
    pub fn as_blob(&self) -> Option<&[u8]> { match &self.value { FsValue::Blob(b) => Some(b), _ => None } }
}
