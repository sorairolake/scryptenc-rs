//
// SPDX-License-Identifier: Apache-2.0 OR MIT
//
// Copyright (C) 2022 Shun Sakai
//

//! Error types for this crate.

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
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn display() {
        assert_eq!(
            format!("{}", Error::InvalidLength(usize::MIN)),
            "encrypted data size `0` bytes is too small"
        );
        assert_eq!(
            format!("{}", Error::InvalidMagicNumber),
            "invalid magic number"
        );
        assert_eq!(
            format!("{}", Error::UnknownVersion(u8::MAX)),
            "unknown version number `255`"
        );
        assert_eq!(
            format!("{}", Error::InvalidParams(InvalidParams)),
            "invalid scrypt parameters"
        );
        assert_eq!(format!("{}", Error::InvalidChecksum), "checksum mismatch");
        assert_eq!(
            format!("{}", Error::InvalidSignature(MacError)),
            "MAC tag mismatch"
        );
    }

    #[test]
    fn invalid_params_to_error() {
        assert!(matches!(
            Error::from(InvalidParams),
            Error::InvalidParams(InvalidParams)
        ));
    }

    #[test]
    fn mac_error_to_error() {
        assert!(matches!(
            Error::from(MacError),
            Error::InvalidSignature(MacError)
        ));
    }
}
