//
// SPDX-License-Identifier: Apache-2.0 OR MIT
//
// Copyright (C) 2022 Shun Sakai
//

//! Encrypts to the scrypt encrypted data format.

use aes::{
    cipher::{generic_array::GenericArray, KeyIvInit, StreamCipher},
    Aes256,
};
use ctr::Ctr128BE;
use scrypt::Params;

use crate::format::{self, DerivedKey, Header, Signature};

/// Encryptor for the scrypt encrypted data format.
#[derive(Clone, Debug)]
pub struct Encryptor {
    header: Header,
    dk: DerivedKey,
    data: Vec<u8>,
}

impl Encryptor {
    /// Creates a new `Encryptor`.
    ///
    /// This uses the recommended values for the scrypt parameters which is
    /// sufficient for most use-cases.
    pub fn new(password: impl AsRef<[u8]>, data: impl AsRef<[u8]>) -> Self {
        Self::with_params(password, Params::recommended(), data)
    }

    #[allow(clippy::missing_panics_doc)]
    /// Creates a new `Encryptor`.
    pub fn with_params(password: impl AsRef<[u8]>, params: Params, data: impl AsRef<[u8]>) -> Self {
        let inner = |password: &[u8], params: Params, data: &[u8]| -> Self {
            let mut header = Header::new(params);

            let mut dk: [u8; 64] = [u8::default(); 64];
            scrypt::scrypt(password, &header.salt(), &params, &mut dk).unwrap();
            let dk = DerivedKey::new(dk);

            header.compute_checksum();
            header.compute_signature(&dk);

            let data = data.to_vec();
            Self { header, dk, data }
        };
        inner(password.as_ref(), params, data.as_ref())
    }

    /// Encrypt data into `buf`.
    ///
    /// # Panics
    ///
    /// Panics if `buf` and the encrypted data have different lengths.
    pub fn encrypt(self, mut buf: impl AsMut<[u8]>) {
        let inner = |encryptor: Self, buf: &mut [u8]| {
            type Aes256Ctr128BE = Ctr128BE<Aes256>;

            let bound = (Header::size(), encryptor.out_len() - Signature::size());

            let mut cipher =
                Aes256Ctr128BE::new(&encryptor.dk.encrypt().into(), &GenericArray::default());
            let mut data = encryptor.data;
            cipher.apply_keystream(&mut data);

            buf[..bound.0].copy_from_slice(&encryptor.header.as_bytes());
            buf[bound.0..bound.1].copy_from_slice(&data);

            let signature = format::compute_signature(&encryptor.dk.mac(), &buf[..bound.1]);
            buf[bound.1..].copy_from_slice(&signature);
        };
        inner(self, buf.as_mut());
    }

    /// Encrypt data and into a newly allocated `Vec`.
    #[must_use]
    pub fn encrypt_to_vec(self) -> Vec<u8> {
        let mut buf = vec![u8::default(); self.out_len()];
        self.encrypt(&mut buf);
        buf
    }

    /// Returns the number of output bytes of the encrypted data.
    #[must_use]
    pub fn out_len(&self) -> usize {
        Header::size() + self.data.len() + Signature::size()
    }
}
