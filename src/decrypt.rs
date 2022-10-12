//
// SPDX-License-Identifier: Apache-2.0 OR MIT
//
// Copyright (C) 2022 Shun Sakai
//

//! Decrypts from the scrypt encrypted data format.

use aes::{
    cipher::{generic_array::GenericArray, KeyIvInit, StreamCipher},
    Aes256,
};
use ctr::Ctr128BE;
use scrypt::Params;

use crate::{
    error::Error,
    format::{self, DerivedKey, Header, Version},
};

/// Decryptor for the scrypt encrypted data format.
#[derive(Debug)]
pub struct Decryptor {
    header: Header,
    dk: DerivedKey,
    data: Vec<u8>,
    signature: [u8; 32],
}

impl Decryptor {
    #[allow(clippy::missing_panics_doc)]
    /// Creates a new `Decryptor`.
    ///
    /// # Errors
    ///
    /// This function will return an error in the following situations:
    ///
    /// - `data` is less than 128 bytes.
    /// - The magic number is not "scrypt".
    /// - The version number other than `0`.
    /// - The scrypt parameters are invalid.
    /// - SHA-256 checksum of the header mismatch.
    /// - HMAC-SHA-256 signature of the header mismatch.
    pub fn new(password: impl AsRef<[u8]>, data: impl AsRef<[u8]>) -> Result<Self, Error> {
        let inner = |password: &[u8], data: &[u8]| -> Result<Self, Error> {
            let length = data.len();
            if length < 128 {
                return Err(Error::InvalidLength(length));
            }

            let header: [u8; 96] = data[..96].try_into().unwrap();
            if &header[..6] != b"scrypt" {
                return Err(Error::InvalidMagicNumber);
            }
            let version = header[6];
            if version != Version::V0.into() {
                return Err(Error::UnknownVersion(version));
            }
            let log_n = header[7];
            let r = u32::from_be_bytes(header[8..12].try_into().unwrap());
            let p = u32::from_be_bytes(header[12..16].try_into().unwrap());
            let params = Params::new(log_n, r, p).map_err(Error::from)?;
            let salt: [u8; 32] = header[16..48].try_into().unwrap();

            let process: [u8; 48] = header[..48].try_into().unwrap();
            let checksum = format::compute_checksum(&process);
            if checksum != header[48..64] {
                return Err(Error::InvalidChecksum);
            }

            let mut dk: [u8; 64] = [u8::default(); 64];
            scrypt::scrypt(password, &salt, &params, &mut dk).unwrap();

            let process: [u8; 64] = header[..64].try_into().unwrap();
            format::verify_signature(&dk[32..], &process, &header[64..96])?;

            let header = Header::new(header);
            let dk = DerivedKey::new(dk);
            let (data, signature) = data[96..].split_at(length - 128);
            let data = data.to_vec();
            let signature = signature.try_into().unwrap();
            Ok(Self {
                header,
                dk,
                data,
                signature,
            })
        };
        inner(password.as_ref(), data.as_ref())
    }

    /// Decrypt data into `buf`.
    ///
    /// # Errors
    ///
    /// Returns `Err` if HMAC-SHA-256 signature mismatch.
    ///
    /// # Panics
    ///
    /// Panics if `buf` and the decrypted data have different lengths.
    pub fn decrypt(self, mut buf: impl AsMut<[u8]>) -> Result<(), Error> {
        let inner = |decryptor: Self, buf: &mut [u8]| -> Result<(), Error> {
            type Aes256Ctr128BE = Ctr128BE<Aes256>;

            let input = [decryptor.header.as_bytes().as_slice(), &decryptor.data].concat();

            let dk = decryptor.dk.as_bytes();
            let mut cipher = Aes256Ctr128BE::new(dk[..32].into(), &GenericArray::default());
            let mut data = decryptor.data;
            cipher.apply_keystream(&mut data);

            format::verify_signature(&dk[32..], &input, &decryptor.signature)?;

            buf.copy_from_slice(&data);
            Ok(())
        };
        inner(self, buf.as_mut())
    }

    /// Decrypt data and into a newly allocated `Vec`.
    ///
    /// # Errors
    ///
    /// Returns `Err` if HMAC-SHA-256 signature mismatch.
    pub fn decrypt_to_vec(self) -> Result<Vec<u8>, Error> {
        let mut buf = vec![u8::default(); self.out_len()];
        self.decrypt(&mut buf)?;
        Ok(buf)
    }

    /// Returns the number of output bytes of the decrypted data.
    #[must_use]
    pub fn out_len(&self) -> usize {
        self.data.len()
    }
}
