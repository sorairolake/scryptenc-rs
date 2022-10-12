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
use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha20Rng;
use scrypt::Params;

use crate::format::{self, DerivedKey, Header, Version};

/// Encryptor for the scrypt encrypted data format.
#[derive(Debug)]
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
        Self::with_params(password, &Params::recommended(), data)
    }

    #[allow(clippy::missing_panics_doc)]
    /// Creates a new `Encryptor`.
    pub fn with_params(
        password: impl AsRef<[u8]>,
        params: &Params,
        data: impl AsRef<[u8]>,
    ) -> Self {
        let inner = |password: &[u8], params: &Params, data: &[u8]| -> Self {
            fn generate_salt() -> [u8; 32] {
                let mut rng = ChaCha20Rng::from_entropy();
                rng.gen()
            }

            let salt = generate_salt();

            let mut dk: [u8; 64] = [u8::default(); 64];
            scrypt::scrypt(password, &salt, params, &mut dk).unwrap();

            let mut header: [u8; 96] = [u8::default(); 96];
            header[..6].copy_from_slice(b"scrypt");
            header[6] = Version::V0.into();
            header[7] = params.log_n();
            header[8..12].copy_from_slice(&params.r().to_be_bytes());
            header[12..16].copy_from_slice(&params.p().to_be_bytes());
            header[16..48].copy_from_slice(&salt);

            let processed: [u8; 48] = header[..48].try_into().unwrap();
            header[48..64].copy_from_slice(&format::compute_checksum(&processed));

            let processed: [u8; 64] = header[..64].try_into().unwrap();
            header[64..].copy_from_slice(&format::compute_signature(&dk[32..], &processed));

            let header = Header::new(header);
            let dk = DerivedKey::new(dk);
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

            let out_len = encryptor.out_len();

            let dk = encryptor.dk.as_bytes();
            let mut cipher = Aes256Ctr128BE::new(dk[..32].into(), &GenericArray::default());
            let mut data = encryptor.data;
            cipher.apply_keystream(&mut data);

            buf[..96].copy_from_slice(&encryptor.header.as_bytes());
            buf[96..out_len - 32].copy_from_slice(&data);

            let processed = &buf[..out_len - 32];
            let signature = format::compute_signature(&dk[32..], processed);
            buf[out_len - 32..].copy_from_slice(&signature);
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
        self.data.len() + 128
    }
}
