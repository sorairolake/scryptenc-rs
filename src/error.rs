//
// SPDX-License-Identifier: Apache-2.0 OR MIT
//
// Copyright (C) 2022 Shun Sakai
//

//! Error types for this crate.

use std::io;

use hmac::digest::MacError;
use scrypt::errors::InvalidParams;
use thiserror::Error;

/// The error type for the scrypt encrypted data format.
#[derive(Debug, Error)]
pub enum Error {
    /// The length of the encrypted data was less than 128 bytes.
    #[error("encrypted data size `{0}` bytes is too small")]
    InvalidLength(usize),

    /// The magic number was invalid.
    #[error("invalid magic number")]
    InvalidMagicNumber,

    /// The version was the unrecognized scrypt version number.
    #[error("unknown version number `{0}`")]
    UnknownVersion(u8),

    /// The scrypt parameters were invalid.
    #[error(transparent)]
    InvalidParams(#[from] InvalidParams),

    /// The checksum of the header mismatched.
    #[error("checksum mismatch")]
    InvalidChecksum,

    /// The MAC mismatched.
    #[error(transparent)]
    InvalidSignature(#[from] MacError),

    /// An error occurred during I/O operations.
    #[error(transparent)]
    Io(#[from] io::Error),
}
