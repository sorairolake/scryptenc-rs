//
// SPDX-License-Identifier: Apache-2.0 OR MIT
//
// Copyright (C) 2022 Shun Sakai
//

//! Encrypts to the scrypt encrypted data format.

use std::io::Write;

use aes::{
    cipher::{generic_array::GenericArray, KeyIvInit, StreamCipher},
    Aes256,
};
use ctr::Ctr128BE;
use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha20Rng;
use scrypt::Params;

use crate::{
    error::Error,
    format::{self, DerivedKey, Header, Version},
};

/// Encryptor for the scrypt encrypted data format.
#[derive(Debug)]
pub struct Encryptor {
    header: Header,
    dk: DerivedKey,
    data: Vec<u8>,
}

impl Encryptor {
    #[allow(clippy::missing_panics_doc)]
    /// Creates a new `Encryptor`.
    pub fn new(password: impl AsRef<[u8]>, params: &Params, data: impl AsRef<[u8]>) -> Self {
        fn generate_salt() -> [u8; 32] {
            let mut rng = ChaCha20Rng::from_entropy();
            rng.gen()
        }

        let salt = generate_salt();

        let mut dk: [u8; 64] = [u8::default(); 64];
        scrypt::scrypt(password.as_ref(), &salt, params, &mut dk).unwrap();

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
        let data = data.as_ref().to_vec();
        Self { header, dk, data }
    }

    /// Encrypt data in place.
    ///
    /// # Errors
    ///
    /// Returns `Err` if I/O operations fails.
    pub fn encrypt(self, mut buf: impl Write) -> Result<(), Error> {
        type Aes256Ctr128BE = Ctr128BE<Aes256>;

        let dk = self.dk.as_bytes();
        let mut cipher = Aes256Ctr128BE::new(dk[..32].into(), &GenericArray::default());
        let mut data = self.data;
        cipher.apply_keystream(&mut data);

        let mut output = self.header.as_bytes().to_vec();
        output.append(&mut data);

        let processed = output.clone();
        let signature = format::compute_signature(&dk[32..], &processed);
        output.extend_from_slice(&signature);

        buf.write_all(&output)?;
        Ok(())
    }

    /// Encrypt data and into a newly allocated `Vec`.
    ///
    /// # Errors
    ///
    /// Returns `Err` if I/O operations fails.
    pub fn encrypt_to_vec(self) -> Result<Vec<u8>, Error> {
        let mut buf = Vec::new();
        self.encrypt(&mut buf)?;
        Ok(buf)
    }
}
