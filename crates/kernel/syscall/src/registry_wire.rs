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
pub const QUERY_KEY: u8 = 12;
pub const DELETE_KEY: u8 = 14;
pub const DELETE_VALUE: u8 = 13;
pub const SAVE_HIVE: u8 = 15;
pub const LOAD_HIVE_ROOT: u8 = 16;
pub const QUERY_PATH: u8 = 17;
pub const SUBSCRIBE: u8 = 18;
pub const POLL_SUBSCRIPTION: u8 = 19;
pub const UNSUBSCRIBE: u8 = 20;
pub const LOAD_HIVE_RELATIVE: u8 = 21;

pub const RESPONSE_SUCCESS: u8 = 0;
pub const RESPONSE_HANDLE: u8 = 1;
pub const RESPONSE_VALUE: u8 = 2;
pub const RESPONSE_FAILURE: u8 = 3;
pub const RESPONSE_KEYS: u8 = 4;
pub const RESPONSE_VALUES: u8 = 5;
pub const RESPONSE_KEY_INFO: u8 = 6;
pub const RESPONSE_BYTES: u8 = 7;
pub const RESPONSE_TEXT: u8 = 8;
pub const RESPONSE_SUBSCRIPTION: u8 = 9;
pub const RESPONSE_NOTIFICATION: u8 = 10;

pub const ERROR_INVALID_PATH: u8 = 1;
pub const ERROR_MISSING_KEY: u8 = 2;
pub const ERROR_MISSING_VALUE: u8 = 3;
pub const ERROR_INVALID_FILE: u8 = 4;
pub const ERROR_IO: u8 = 5;
pub const ERROR_DELETED: u8 = 6;

pub const MAX_FRAME: usize = 1 << 24;
