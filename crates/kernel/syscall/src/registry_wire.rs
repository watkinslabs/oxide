//! Shared wire vocabulary for the native registry service.

#![allow(dead_code)]

pub const OPEN: u8 = 1;
pub const CREATE: u8 = 2;
pub const SET: u8 = 3;
pub const QUERY: u8 = 4;
pub const CLOSE: u8 = 5;
pub const ENUM_KEYS: u8 = 6;
pub const ENUM_VALUES: u8 = 7;
pub const OPEN_RELATIVE: u8 = 8;
pub const CREATE_RELATIVE: u8 = 9;
pub const RENAME: u8 = 10;
pub const FLUSH: u8 = 11;

pub const RESPONSE_SUCCESS: u8 = 0;
pub const RESPONSE_HANDLE: u8 = 1;
pub const RESPONSE_VALUE: u8 = 2;
pub const RESPONSE_FAILURE: u8 = 3;

pub const ERROR_INVALID_PATH: u8 = 1;
pub const ERROR_MISSING_KEY: u8 = 2;
pub const ERROR_MISSING_VALUE: u8 = 3;
pub const ERROR_INVALID_FILE: u8 = 4;
pub const ERROR_IO: u8 = 5;

pub const MAX_FRAME: usize = 1 << 24;
