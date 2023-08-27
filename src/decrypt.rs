// SPDX-FileCopyrightText: 2022 Shun Sakai
//
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! Decrypts from the scrypt encrypted data format.

use alloc::vec::Vec;

use aes::cipher::{generic_array::GenericArray, KeyIvInit, StreamCipher};
use hmac::{
    digest::{typenum::Unsigned, OutputSizeUser},
    Mac,
};

use crate::{
    error::Error,
    format::{DerivedKey, Header},
    Aes256Ctr128BE, HmacSha256, HmacSha256Key, HmacSha256Output,
};

/// Decryptor for the scrypt encrypted data format.
#[derive(Clone, Debug)]
pub struct Decryptor {
    header: Header,
    dk: DerivedKey,
    ciphertext: Vec<u8>,
    mac: HmacSha256Output,
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
    /// - HMAC-SHA-256 of the header is invalid.
    ///
    /// # Examples
    ///
    /// ```
    /// # use scryptenc::{scrypt::Params, Decryptor, Encryptor};
    /// #
    /// let data = b"Hello, world!";
    /// let password = "password";
    ///
    /// let params = Params::new(10, 8, 1, Params::RECOMMENDED_LEN).unwrap();
    /// let encrypted = Encryptor::with_params(data, password, params).encrypt_to_vec();
    /// # assert_ne!(encrypted, data);
    ///
    /// let cipher = Decryptor::new(encrypted, password).unwrap();
    /// let decrypted = cipher.decrypt_to_vec().unwrap();
    /// # assert_eq!(decrypted, data);
    /// ```
    pub fn new(data: impl AsRef<[u8]>, password: impl AsRef<[u8]>) -> Result<Self, Error> {
        let inner = |data: &[u8], password: &[u8]| -> Result<Self, Error> {
            let mut header = Header::parse(data)?;

            header.verify_checksum(&data[48..64])?;

            // The derived key size is 64 bytes. The first 256 bits are for AES-256-CTR key,
            // and the last 256 bits are for HMAC-SHA-256 key.
            let mut dk = [u8::default(); DerivedKey::SIZE];
            scrypt::scrypt(password, &header.salt(), &header.params(), &mut dk)
                .expect("derived key size should be 64 bytes");
            let dk = DerivedKey::new(dk);

            header.verify_mac(&dk.mac(), data[64..Header::SIZE].into())?;

            let (ciphertext, mac) = data[Header::SIZE..].split_at(
                data.len() - Header::SIZE - <HmacSha256 as OutputSizeUser>::OutputSize::USIZE,
            );
            let ciphertext = ciphertext.to_vec();
            let mac = HmacSha256Output::clone_from_slice(mac);
            Ok(Self {
                header,
                dk,
                ciphertext,
                mac,
            })
        };
        inner(data.as_ref(), password.as_ref())
    }

    /// Decrypts data into `buf`.
    ///
    /// # Errors
    ///
    /// Returns `Err` if HMAC-SHA-256 at EOF is invalid.
    ///
    /// # Panics
    ///
    /// Panics if `buf` and the decrypted data have different lengths.
    ///
    /// # Examples
    ///
    /// ```
    /// # use scryptenc::{scrypt::Params, Decryptor, Encryptor};
    /// #
    /// let data = b"Hello, world!";
    /// let password = "password";
    ///
    /// let params = Params::new(10, 8, 1, Params::RECOMMENDED_LEN).unwrap();
    /// let encrypted = Encryptor::with_params(data, password, params).encrypt_to_vec();
    /// # assert_ne!(encrypted, data);
    ///
    /// let cipher = Decryptor::new(encrypted, password).unwrap();
    /// let mut buf = [u8::default(); 13];
    /// cipher.decrypt(&mut buf).unwrap();
    /// # assert_eq!(buf, data.as_slice());
    /// ```
    pub fn decrypt(self, mut buf: impl AsMut<[u8]>) -> Result<(), Error> {
        let inner = |decryptor: Self, buf: &mut [u8]| -> Result<(), Error> {
            fn verify_mac(
                data: &[u8],
                key: &HmacSha256Key,
                tag: &HmacSha256Output,
            ) -> Result<(), Error> {
                let mut mac = HmacSha256::new_from_slice(key)
                    .expect("HMAC-SHA-256 key size should be 256 bits");
                mac.update(data);
                mac.verify(tag).map_err(Error::InvalidMac)
            }

            let input = [
                decryptor.header.as_bytes().as_slice(),
                &decryptor.ciphertext,
            ]
            .concat();

            let mut cipher = Aes256Ctr128BE::new(&decryptor.dk.encrypt(), &GenericArray::default());
            let mut data = decryptor.ciphertext;
            cipher.apply_keystream(&mut data);

            verify_mac(&input, &decryptor.dk.mac(), &decryptor.mac)?;

            buf.copy_from_slice(&data);
            Ok(())
        };
        inner(self, buf.as_mut())
    }

    /// Decrypts data and into a newly allocated `Vec`.
    ///
    /// # Errors
    ///
    /// Returns `Err` if HMAC-SHA-256 at EOF is invalid.
    ///
    /// # Examples
    ///
    /// ```
    /// # use scryptenc::{scrypt::Params, Decryptor, Encryptor};
    /// #
    /// let data = b"Hello, world!";
    /// let password = "password";
    ///
    /// let params = Params::new(10, 8, 1, Params::RECOMMENDED_LEN).unwrap();
    /// let encrypted = Encryptor::with_params(data, password, params).encrypt_to_vec();
    /// # assert_ne!(encrypted, data);
    ///
    /// let cipher = Decryptor::new(encrypted, password).unwrap();
    /// let decrypted = cipher.decrypt_to_vec().unwrap();
    /// # assert_eq!(decrypted, data);
    /// ```
    pub fn decrypt_to_vec(self) -> Result<Vec<u8>, Error> {
        let mut buf = vec![u8::default(); self.out_len()];
        self.decrypt(&mut buf)?;
        Ok(buf)
    }

    /// Returns the number of output bytes of the decrypted data.
    ///
    /// # Examples
    ///
    /// ```
    /// # use scryptenc::{scrypt::Params, Decryptor, Encryptor};
    /// #
    /// let data = b"Hello, world!";
    /// let password = "password";
    ///
    /// let params = Params::new(10, 8, 1, Params::RECOMMENDED_LEN).unwrap();
    /// let encrypted = Encryptor::with_params(data, password, params).encrypt_to_vec();
    /// # assert_ne!(encrypted, data);
    ///
    /// let cipher = Decryptor::new(encrypted, password).unwrap();
    /// assert_eq!(cipher.out_len(), 13);
    /// ```
    #[must_use]
    #[inline]
    pub fn out_len(&self) -> usize {
        self.ciphertext.len()
    }
}
