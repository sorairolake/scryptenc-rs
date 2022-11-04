//
// SPDX-License-Identifier: Apache-2.0 OR MIT
//
// Copyright (C) 2022 Shun Sakai
//

//! Decrypts from the scrypt encrypted data format.

use alloc::vec::Vec;

use aes::{
    cipher::{generic_array::GenericArray, KeyIvInit, StreamCipher},
    Aes256,
};
use ctr::Ctr128BE;

use crate::{
    error::Error,
    format::{self, DerivedKey, Header, Signature},
};

/// Decryptor for the scrypt encrypted data format.
#[derive(Clone, Debug)]
pub struct Decryptor {
    header: Header,
    dk: DerivedKey,
    data: Vec<u8>,
    signature: Signature,
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
    pub fn new(data: impl AsRef<[u8]>, password: impl AsRef<[u8]>) -> Result<Self, Error> {
        let inner = |data: &[u8], password: &[u8]| -> Result<Self, Error> {
            let mut header = Header::parse(data)?;

            header.verify_checksum(&data[48..64])?;

            // The derived key size is 64 bytes.
            // The first 256 bits are for AES-256-CTR key, and the last 256 bits are for
            // HMAC-SHA-256 key.
            let mut dk = [u8::default(); 64];
            scrypt::scrypt(password, &header.salt(), &header.params(), &mut dk)
                .expect("derived key size should be 64 bytes");
            let dk = DerivedKey::new(dk);

            header.verify_signature(&dk, &data[64..Header::size()])?;

            let (data, signature) =
                data[Header::size()..].split_at(data.len() - Header::size() - Signature::size());
            let data = data.to_vec();
            let signature = Signature::new(
                signature
                    .try_into()
                    .expect("output size of HMAC-SHA-256 should be 256 bits"),
            );
            Ok(Self {
                header,
                dk,
                data,
                signature,
            })
        };
        inner(data.as_ref(), password.as_ref())
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

            let mut cipher =
                Aes256Ctr128BE::new(&decryptor.dk.encrypt().into(), &GenericArray::default());
            let mut data = decryptor.data;
            cipher.apply_keystream(&mut data);

            format::verify_signature(&decryptor.dk.mac(), &input, &decryptor.signature.as_bytes())?;

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
    #[inline]
    pub fn out_len(&self) -> usize {
        self.data.len()
    }
}
