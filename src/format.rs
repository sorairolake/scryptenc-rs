// SPDX-FileCopyrightText: 2022 Shun Sakai
//
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! Specifications of the scrypt encrypted data format.

use core::mem;

use ctr::cipher::{self, KeySizeUser};
use hmac::{
    digest::{
        typenum::{Unsigned, U32},
        OutputSizeUser,
    },
    Mac,
};
use rand::{rngs::StdRng, Rng, SeedableRng};
use sha2::{Digest, Sha256};

use crate::{
    error::{Error, Result},
    Aes256Ctr128BE, HmacSha256, HmacSha256Key, HmacSha256Output, Params,
};

/// A type alias for magic number of the scrypt encrypted data format.
type MagicNumber = [u8; 6];

/// A type alias for salt of scrypt.
type Salt = [u8; 32];

/// A type alias for checksum of the scrypt encrypted data format.
type Checksum = [u8; 16];

/// A type alias for the header MAC.
type HeaderMac = HmacSha256;

/// A type alias for output of the header MAC.
type HeaderMacOutput = HmacSha256Output;

/// A type alias for key of the header MAC.
type HeaderMacKey = HmacSha256Key;

/// A type alias for key of AES-256-CTR.
type Aes256Ctr128BEKey = cipher::Key<Aes256Ctr128BE>;

/// The number of bytes of the header.
pub const HEADER_SIZE: usize = Header::SIZE;

/// The number of bytes of the MAC (authentication tag) of the scrypt encrypted
/// data format.
pub const TAG_SIZE: usize = <HmacSha256 as OutputSizeUser>::OutputSize::USIZE;

/// Version of the scrypt encrypted data format.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum Version {
    /// Version 0.
    #[default]
    V0,

    /// Version 1.
    _V1,
}

impl From<Version> for u8 {
    fn from(version: Version) -> Self {
        version as Self
    }
}

/// Header of the scrypt encrypted data format.
#[derive(Clone, Debug)]
pub struct Header {
    magic_number: MagicNumber,
    version: Version,
    params: Params,
    salt: Salt,
    checksum: Checksum,
    mac: HeaderMacOutput,
}

impl Header {
    /// Magic number of the scrypt encrypted data format.
    ///
    /// This is the ASCII code for "scrypt".
    const MAGIC_NUMBER: MagicNumber = *b"scrypt";

    /// The number of bytes of the header.
    const SIZE: usize = mem::size_of::<MagicNumber>()
        + mem::size_of::<Version>()
        + (mem::size_of::<Params>() - (mem::align_of::<Params>() - mem::size_of::<u8>()))
        + mem::size_of::<Salt>()
        + mem::size_of::<Checksum>()
        + <HeaderMac as OutputSizeUser>::OutputSize::USIZE;

    /// Creates a new `Header`.
    pub fn new(params: scrypt::Params) -> Self {
        let magic_number = Self::MAGIC_NUMBER;
        let version = Version::default();
        let params = params.into();
        let salt = StdRng::from_entropy().gen();
        let checksum = Checksum::default();
        let mac = HeaderMacOutput::default();
        Self {
            magic_number,
            version,
            params,
            salt,
            checksum,
            mac,
        }
    }

    /// Parses `data` into the header.
    pub fn parse(data: &[u8]) -> Result<Self> {
        if data.len() < Self::SIZE + TAG_SIZE {
            return Err(Error::InvalidLength);
        }

        let Some(magic_number) = Some(Self::MAGIC_NUMBER).filter(|mn| &data[..6] == mn) else {
            return Err(Error::InvalidMagicNumber);
        };
        let version = match data[6] {
            0 => Version::V0,
            v => return Err(Error::UnknownVersion(v)),
        };
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
            .map(Params::from)
            .map_err(Error::from)?;
        let salt = data[16..48]
            .try_into()
            .expect("size of salt should be 32 bytes");
        let checksum = Checksum::default();
        let mac = HeaderMacOutput::default();
        Ok(Self {
            magic_number,
            version,
            params,
            salt,
            checksum,
            mac,
        })
    }

    /// Gets a SHA-256 checksum of this header.
    pub fn compute_checksum(&mut self) {
        let result = Sha256::digest(&self.as_bytes()[..48]);
        self.checksum.copy_from_slice(&result[..16]);
    }

    /// Verifies a SHA-256 checksum stored in this header.
    pub fn verify_checksum(&mut self, checksum: &[u8]) -> Result<()> {
        self.compute_checksum();
        if self.checksum == checksum {
            Ok(())
        } else {
            Err(Error::InvalidChecksum)
        }
    }

    /// Gets a HMAC-SHA-256 of this header.
    pub fn compute_mac(&mut self, key: &HeaderMacKey) {
        let mut mac =
            HmacSha256::new_from_slice(key).expect("HMAC-SHA-256 key size should be 256 bits");
        mac.update(&self.as_bytes()[..64]);
        self.mac.copy_from_slice(&mac.finalize().into_bytes());
    }

    /// Verifies a HMAC-SHA-256 stored in this header.
    pub fn verify_mac(&mut self, key: &HeaderMacKey, tag: &HeaderMacOutput) -> Result<()> {
        let mut mac =
            HmacSha256::new_from_slice(key).expect("HMAC-SHA-256 key size should be 256 bits");
        mac.update(&self.as_bytes()[..64]);
        mac.verify(tag).map_err(Error::InvalidHeaderMac)?;
        self.mac.copy_from_slice(tag);
        Ok(())
    }

    /// Converts this header to a byte array.
    pub fn as_bytes(&self) -> [u8; Self::SIZE] {
        let mut header = [u8::default(); Self::SIZE];
        header[..6].copy_from_slice(&self.magic_number);
        header[6] = self.version.into();
        header[7] = self.params.log_n();
        header[8..12].copy_from_slice(&self.params.r().to_be_bytes());
        header[12..16].copy_from_slice(&self.params.p().to_be_bytes());
        header[16..48].copy_from_slice(&self.salt);
        header[48..64].copy_from_slice(&self.checksum);
        header[64..].copy_from_slice(&self.mac);
        header
    }

    /// Returns the scrypt parameters stored in this header.
    pub const fn params(&self) -> Params {
        self.params
    }

    /// Returns a salt stored in this header.
    pub const fn salt(&self) -> Salt {
        self.salt
    }
}

/// Derived key.
#[derive(Clone, Debug)]
pub struct DerivedKey {
    encrypt: Aes256Ctr128BEKey,
    mac: HmacSha256Key,
}

impl DerivedKey {
    /// The number of bytes of the derived key.
    pub const SIZE: usize = <Aes256Ctr128BE as KeySizeUser>::KeySize::USIZE + U32::USIZE;

    /// Creates a new `DerivedKey`.
    pub fn new(dk: [u8; Self::SIZE]) -> Self {
        let encrypt = Aes256Ctr128BEKey::clone_from_slice(&dk[..32]);
        let mac = HmacSha256Key::clone_from_slice(&dk[32..]);
        Self { encrypt, mac }
    }

    /// Returns the key for encrypted.
    pub const fn encrypt(&self) -> Aes256Ctr128BEKey {
        self.encrypt
    }

    /// Returns the key for a MAC.
    pub const fn mac(&self) -> HmacSha256Key {
        self.mac
    }
}

#[cfg(test)]
mod tests {
    use core::str;

    use super::*;

    #[test]
    fn header_size() {
        assert_eq!(HEADER_SIZE, 96);
        assert_eq!(HEADER_SIZE, Header::SIZE);
    }

    #[test]
    fn tag_size() {
        assert_eq!(TAG_SIZE, 32);
        assert_eq!(TAG_SIZE, <HmacSha256 as OutputSizeUser>::OutputSize::USIZE);
    }

    #[test]
    fn version() {
        assert_eq!(Version::V0 as u8, 0);
        assert_eq!(Version::_V1 as u8, 1);
    }

    #[test]
    fn size_of_version() {
        assert_eq!(mem::size_of::<Version>(), mem::size_of::<u8>());
    }

    #[test]
    fn clone_version() {
        assert_eq!(Version::V0.clone(), Version::V0);
        assert_eq!(Version::_V1.clone(), Version::_V1);
    }

    #[test]
    fn copy_version() {
        {
            let a = Version::V0;
            let b = a;
            assert_eq!(a, b);
        }

        {
            let a = Version::_V1;
            let b = a;
            assert_eq!(a, b);
        }
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn debug_version() {
        assert_eq!(format!("{:?}", Version::V0), "V0");
        assert_eq!(format!("{:?}", Version::_V1), "_V1");
    }

    #[test]
    fn default_version() {
        assert_eq!(Version::default(), Version::V0);
    }

    #[test]
    fn version_equality() {
        assert_eq!(Version::V0, Version::V0);
        assert_ne!(Version::V0, Version::_V1);
        assert_ne!(Version::_V1, Version::V0);
        assert_eq!(Version::_V1, Version::_V1);
    }

    #[test]
    fn from_version_to_u8() {
        assert_eq!(u8::from(Version::V0), 0);
        assert_eq!(u8::from(Version::_V1), 1);
    }

    #[test]
    fn magic_number() {
        assert_eq!(str::from_utf8(&Header::MAGIC_NUMBER).unwrap(), "scrypt");
    }

    #[test]
    fn derived_key_size() {
        assert_eq!(DerivedKey::SIZE, 64);
    }
}
