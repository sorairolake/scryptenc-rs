//
// SPDX-License-Identifier: Apache-2.0 OR MIT
//
// Copyright (C) 2022-2023 Shun Sakai
//

//! Specifications of the scrypt encrypted data format.

use hmac::{digest::MacError, Hmac, Mac};
use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha20Rng;
use sha2::{Digest, Sha256};

use crate::error::Error;

/// Version of the scrypt data file.
#[derive(Clone, Copy, Debug)]
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
#[derive(Clone, Debug)]
pub struct Header {
    magic_number: [u8; 6],
    version: Version,
    params: scrypt::Params,
    salt: [u8; 32],
    checksum: [u8; 16],
    signature: [u8; 32],
}

impl Header {
    /// Magic number of the scrypt encrypted data format.
    ///
    /// This is the ASCII code for "scrypt".
    const MAGIC_NUMBER: [u8; 6] = [0x73, 0x63, 0x72, 0x79, 0x70, 0x74];

    /// Creates a new `Header`.
    pub fn new(params: scrypt::Params) -> Self {
        fn generate_salt() -> [u8; 32] {
            let mut rng = ChaCha20Rng::from_entropy();
            rng.gen()
        }

        let magic_number = Self::MAGIC_NUMBER;
        let version = Version::V0;
        let salt = generate_salt();

        let checksum = Default::default();
        let signature = Default::default();

        Self {
            magic_number,
            version,
            params,
            salt,
            checksum,
            signature,
        }
    }

    /// Parses `data` into the header.
    pub fn parse(data: &[u8]) -> Result<Self, Error> {
        if data.len() < 128 {
            return Err(Error::InvalidLength);
        }

        let magic_number = if data[..6] == Self::MAGIC_NUMBER {
            Ok(Self::MAGIC_NUMBER)
        } else {
            Err(Error::InvalidMagicNumber)
        }?;
        let version = if data[6] == Version::V0.into() {
            Ok(Version::V0)
        } else {
            Err(Error::UnknownVersion(data[6]))
        }?;
        let log_n = data[7];
        let r = u32::from_be_bytes(
            data[8..12]
                .try_into()
                .expect("size of `r` parameter should be 4 bytes"),
        );
        let p = u32::from_be_bytes(
            data[12..16]
                .try_into()
                .expect("size of `p` parameter should be 4 bytes"),
        );
        let params = scrypt::Params::new(log_n, r, p, scrypt::Params::RECOMMENDED_LEN)
            .map_err(Error::from)?;
        let salt = data[16..48]
            .try_into()
            .expect("size of salt should be 32 bytes");

        let checksum = Default::default();
        let signature = Default::default();

        Ok(Self {
            magic_number,
            version,
            params,
            salt,
            checksum,
            signature,
        })
    }

    /// Gets a SHA-256 checksum of this header.
    pub fn compute_checksum(&mut self) {
        let result = Sha256::digest(&self.as_bytes()[..48]);
        self.checksum.copy_from_slice(&result[..16]);
    }

    /// Verifies a SHA-256 checksum stored in this header.
    pub fn verify_checksum(&mut self, checksum: &[u8]) -> Result<(), Error> {
        self.compute_checksum();
        if self.checksum == checksum {
            Ok(())
        } else {
            Err(Error::InvalidChecksum)
        }
    }

    /// Gets a HMAC-SHA-256 signature of this header.
    pub fn compute_signature(&mut self, key: &DerivedKey) {
        let mac = compute_signature(&key.mac(), &self.as_bytes()[..64]);
        self.signature.copy_from_slice(&mac);
    }

    /// Verifies a HMAC-SHA-256 signature stored in this header.
    pub fn verify_signature(&mut self, key: &DerivedKey, signature: &[u8]) -> Result<(), Error> {
        verify_signature(&key.mac(), &self.as_bytes()[..64], signature)?;
        self.signature.copy_from_slice(signature);
        Ok(())
    }

    /// Converts this header to a byte array.
    pub fn as_bytes(&self) -> [u8; 96] {
        let mut header = [u8::default(); 96];
        header[..6].copy_from_slice(&self.magic_number);
        header[6] = self.version.into();
        header[7] = self.params.log_n();
        header[8..12].copy_from_slice(&self.params.r().to_be_bytes());
        header[12..16].copy_from_slice(&self.params.p().to_be_bytes());
        header[16..48].copy_from_slice(&self.salt);

        header[48..64].copy_from_slice(&self.checksum);
        header[64..].copy_from_slice(&self.signature);

        header
    }

    /// Returns the scrypt parameters stored in this header.
    pub const fn params(&self) -> scrypt::Params {
        self.params
    }

    /// Returns a salt stored in this header.
    pub const fn salt(&self) -> [u8; 32] {
        self.salt
    }

    /// Returns the number of bytes of the header.
    pub const fn size() -> usize {
        96
    }
}

/// Derived key.
#[derive(Clone, Debug)]
pub struct DerivedKey {
    encrypt: [u8; 32],
    mac: [u8; 32],
}

impl DerivedKey {
    /// Creates a new `DerivedKey`.
    pub fn new(dk: [u8; 64]) -> Self {
        let encrypt = dk[..32]
            .try_into()
            .expect("AES-256-CTR key size should be 256 bits");
        let mac = dk[32..]
            .try_into()
            .expect("HMAC-SHA-256 key size should be 256 bits");
        Self { encrypt, mac }
    }

    /// Returns the key for encrypted.
    pub const fn encrypt(&self) -> [u8; 32] {
        self.encrypt
    }

    /// Returns the key for a MAC.
    pub const fn mac(&self) -> [u8; 32] {
        self.mac
    }
}

/// Signature of the scrypt encrypted data format.
#[derive(Clone, Debug)]
pub struct Signature([u8; 32]);

impl Signature {
    /// Creates a new `Signature`.
    pub const fn new(signature: [u8; 32]) -> Self {
        Self(signature)
    }

    /// Converts this signature to a byte array.
    pub const fn as_bytes(&self) -> [u8; 32] {
        self.0
    }

    /// Returns the number of bytes of the signature.
    pub const fn size() -> usize {
        32
    }
}

/// The scrypt parameters used for the encrypted data.
#[derive(Clone, Copy, Debug)]
pub struct Params(scrypt::Params);

impl Params {
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
        let params = Header::parse(data.as_ref()).map(|h| h.params())?;
        Ok(Self(params))
    }

    /// Gets log2 of the scrypt parameter `N`.
    #[must_use]
    #[inline]
    pub fn log_n(&self) -> u8 {
        self.0.log_n()
    }

    /// Gets `N` parameter.
    #[must_use]
    #[inline]
    pub fn n(&self) -> u64 {
        1 << self.0.log_n()
    }

    /// Gets `r` parameter.
    #[must_use]
    #[inline]
    pub fn r(&self) -> u32 {
        self.0.r()
    }

    /// Gets `p` parameter.
    #[must_use]
    #[inline]
    pub fn p(&self) -> u32 {
        self.0.p()
    }
}

/// Gets a HMAC-SHA-256 signature.
pub fn compute_signature(key: &[u8], data: &[u8]) -> [u8; 32] {
    type HmacSha256 = Hmac<Sha256>;

    let mut mac =
        HmacSha256::new_from_slice(key).expect("HMAC-SHA-256 key size should be 256 bits");
    mac.update(data);
    mac.finalize().into_bytes().into()
}

/// Verifies a HMAC-SHA-256 signature.
pub fn verify_signature(key: &[u8], data: &[u8], signature: &[u8]) -> Result<(), MacError> {
    type HmacSha256 = Hmac<Sha256>;

    let mut mac =
        HmacSha256::new_from_slice(key).expect("HMAC-SHA-256 key size should be 256 bits");
    mac.update(data);
    mac.verify(signature.into())
}

#[cfg(test)]
mod tests {
    use core::str;

    use super::*;

    #[test]
    fn version() {
        assert_eq!(Version::V0 as u8, 0);
    }

    #[test]
    fn magic_number() {
        assert_eq!(str::from_utf8(&Header::MAGIC_NUMBER).unwrap(), "scrypt");
    }

    #[test]
    fn header_size() {
        assert_eq!(Header::size(), 96);
    }

    #[test]
    fn signature_size() {
        assert_eq!(Signature::size(), 32);
    }
}
