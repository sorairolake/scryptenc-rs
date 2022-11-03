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
    /// The encrypted data was shorter than 128 bytes.
    #[error("encrypted data is shorter than 128 bytes")]
    InvalidLength,

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

    /// The signature was invalid.
    #[error("invalid signature")]
    InvalidSignature(
        #[from]
        #[source]
        MacError,
    ),
}

#[cfg(test)]
mod tests {
    use std::error::Error as _;

    use super::*;

    #[test]
    fn display() {
        assert_eq!(
            format!("{}", Error::InvalidLength),
            "encrypted data is shorter than 128 bytes"
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
            "invalid signature"
        );
    }

    #[test]
    fn source() {
        assert!(Error::InvalidLength.source().is_none());
        assert!(Error::InvalidMagicNumber.source().is_none());
        assert!(Error::UnknownVersion(u8::MAX).source().is_none());
        assert!(Error::InvalidParams(InvalidParams).source().is_none());
        assert!(Error::InvalidChecksum.source().is_none());
        assert!(Error::InvalidSignature(MacError)
            .source()
            .unwrap()
            .is::<MacError>());
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
