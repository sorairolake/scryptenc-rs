//
// SPDX-License-Identifier: Apache-2.0 OR MIT
//
// Copyright (C) 2022 Shun Sakai
//

//! Specifications of the scrypt encrypted data format.

use hmac::{digest::MacError, Hmac, Mac};
use sha2::{Digest, Sha256};

use crate::error::Error;

/// Version of the scrypt data file.
#[derive(Debug)]
pub enum Version {
    /// Version 0.
    V0,
}

impl From<Version> for u8 {
    fn from(version: Version) -> Self {
        version as Self
    }
}

/// Header of the scrypt encrypted data format.
#[derive(Debug)]
pub struct Header {
    inner: [u8; 96],
}

impl Header {
    pub const fn new(header: [u8; 96]) -> Self {
        Self { inner: header }
    }

    pub const fn as_bytes(&self) -> [u8; 96] {
        self.inner
    }
}

/// Derived key.
#[derive(Debug)]
pub struct DerivedKey {
    inner: [u8; 64],
}

impl DerivedKey {
    pub const fn new(dk: [u8; 64]) -> Self {
        Self { inner: dk }
    }

    pub const fn as_bytes(&self) -> [u8; 64] {
        self.inner
    }
}

/// The scrypt parameters.
#[derive(Debug)]
pub struct Params {
    log_n: u8,
    r: u32,
    p: u32,
}

impl Params {
    #[allow(clippy::missing_panics_doc)]
    /// Creates a new instance of the scrypt parameters from `data`.
    ///
    /// # Errors
    ///
    /// This function will return an error in the following situations:
    ///
    /// - `data` is less than 128 bytes.
    /// - The magic number is not "scrypt".
    /// - The version number other than `0`.
    /// - The scrypt parameters are invalid.
    pub fn new(data: impl AsRef<[u8]>) -> Result<Self, Error> {
        let data = data.as_ref();

        let length = data.len();
        if length < 128 {
            return Err(Error::InvalidLength(length));
        }

        if &data[..6] != b"scrypt" {
            return Err(Error::InvalidMagicNumber);
        }
        let version = data[6];
        if version != Version::V0.into() {
            return Err(Error::UnknownVersion(version));
        }
        let log_n = data[7];
        let r = u32::from_be_bytes(data[8..12].try_into().unwrap());
        let p = u32::from_be_bytes(data[12..16].try_into().unwrap());
        let params = scrypt::Params::new(log_n, r, p).map_err(Error::from)?;
        Ok(Self {
            log_n: params.log_n(),
            r: params.r(),
            p: params.p(),
        })
    }

    /// Gets log2 of the scrypt parameter `N`.
    #[must_use]
    pub const fn log_n(&self) -> u8 {
        self.log_n
    }

    /// Gets `N` parameter.
    #[must_use]
    pub const fn n(&self) -> u64 {
        1 << self.log_n
    }

    /// Gets `r` parameter.
    #[must_use]
    pub const fn r(&self) -> u32 {
        self.r
    }

    /// Gets `p` parameter.
    #[must_use]
    pub const fn p(&self) -> u32 {
        self.p
    }
}

pub fn compute_checksum(data: &[u8]) -> [u8; 16] {
    let result = Sha256::digest(data);
    let mut checksum: [u8; 16] = Default::default();
    checksum.copy_from_slice(&result[..16]);
    checksum
}

pub fn compute_signature(key: &[u8], data: &[u8]) -> [u8; 32] {
    type HmacSha256 = Hmac<Sha256>;

    let mut mac = HmacSha256::new_from_slice(key).unwrap();
    mac.update(data);
    mac.finalize().into_bytes().into()
}

pub fn verify_signature(key: &[u8], data: &[u8], signature: &[u8]) -> Result<(), MacError> {
    type HmacSha256 = Hmac<Sha256>;

    let mut mac = HmacSha256::new_from_slice(key).unwrap();
    mac.update(data);
    mac.verify(signature.into())
}
