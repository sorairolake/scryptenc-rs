//
// SPDX-License-Identifier: Apache-2.0 OR MIT
//
// Copyright (C) 2022-2023 Shun Sakai
//

//! Error types for this crate.

use core::fmt;

use hmac::digest::MacError;
use scrypt::errors::InvalidParams;

/// The error type for the scrypt encrypted data format.
#[derive(Debug)]
pub enum Error {
    /// The encrypted data was shorter than 128 bytes.
    InvalidLength,

    /// The magic number was invalid.
    InvalidMagicNumber,

    /// The version was the unrecognized scrypt version number.
    UnknownVersion(u8),

    /// The scrypt parameters were invalid.
    InvalidParams(InvalidParams),

    /// The checksum of the header mismatched.
    InvalidChecksum,

    /// The header signature was invalid.
    InvalidHeaderSignature(MacError),

    /// The signature at EOF was invalid.
    InvalidSignature(MacError),
}

impl fmt::Display for Error {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidLength => write!(f, "encrypted data is shorter than 128 bytes"),
            Self::InvalidMagicNumber => write!(f, "invalid magic number"),
            Self::UnknownVersion(version) => write!(f, "unknown version number `{version}`"),
            Self::InvalidParams(err) => write!(f, "{err}"),
            Self::InvalidChecksum => write!(f, "checksum mismatch"),
            Self::InvalidHeaderSignature(_) => write!(f, "invalid header signature"),
            Self::InvalidSignature(_) => write!(f, "invalid signature"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for Error {
    #[inline]
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::InvalidHeaderSignature(err) | Self::InvalidSignature(err) => Some(err),
            _ => None,
        }
    }
}

impl From<InvalidParams> for Error {
    #[inline]
    fn from(source: InvalidParams) -> Self {
        Self::InvalidParams(source)
    }
}

#[cfg(test)]
mod tests {
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
            format!("{}", Error::InvalidHeaderSignature(MacError)),
            "invalid header signature"
        );
        assert_eq!(
            format!("{}", Error::InvalidSignature(MacError)),
            "invalid signature"
        );
    }

    #[cfg(feature = "std")]
    #[test]
    fn source() {
        use std::error::Error as _;

        assert!(Error::InvalidLength.source().is_none());
        assert!(Error::InvalidMagicNumber.source().is_none());
        assert!(Error::UnknownVersion(u8::MAX).source().is_none());
        assert!(Error::InvalidParams(InvalidParams).source().is_none());
        assert!(Error::InvalidChecksum.source().is_none());
        assert!(Error::InvalidHeaderSignature(MacError)
            .source()
            .unwrap()
            .is::<MacError>());
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
}
