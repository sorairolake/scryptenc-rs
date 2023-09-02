// SPDX-FileCopyrightText: 2022 Shun Sakai
//
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! Decrypts from the scrypt encrypted data format.

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
pub struct Decryptor<'c> {
    header: Header,
    dk: DerivedKey,
    ciphertext: &'c [u8],
    mac: HmacSha256Output,
}

impl<'c> Decryptor<'c> {
    #[allow(clippy::missing_panics_doc)]
    /// Creates a new `Decryptor`.
    ///
    /// # Errors
    ///
    /// This function will return an error in the following situations:
    ///
    /// - `ciphertext` is less than 128 bytes.
    /// - The magic number is not "scrypt".
    /// - The version number other than `0`.
    /// - The scrypt parameters are invalid.
    /// - SHA-256 checksum of the header mismatch.
    /// - HMAC-SHA-256 of the header is invalid.
    ///
    /// # Examples
    ///
    /// ```
    /// # use scryptenc::Decryptor;
    /// #
    /// let ciphertext = include_bytes!("../tests/data/data.txt.enc");
    /// let passphrase = "passphrase";
    ///
    /// let cipher = Decryptor::new(&ciphertext, passphrase).unwrap();
    /// ```
    pub fn new(
        ciphertext: &'c impl AsRef<[u8]>,
        passphrase: impl AsRef<[u8]>,
    ) -> Result<Self, Error> {
        let inner = |ciphertext: &'c [u8], passphrase: &[u8]| -> Result<Self, Error> {
            let mut header = Header::parse(ciphertext)?;

            header.verify_checksum(&ciphertext[48..64])?;

            // The derived key size is 64 bytes. The first 256 bits are for AES-256-CTR key,
            // and the last 256 bits are for HMAC-SHA-256 key.
            let mut dk = [u8::default(); DerivedKey::SIZE];
            scrypt::scrypt(passphrase, &header.salt(), &header.params(), &mut dk)
                .expect("derived key size should be 64 bytes");
            let dk = DerivedKey::new(dk);

            header.verify_mac(&dk.mac(), ciphertext[64..Header::SIZE].into())?;

            let (ciphertext, mac) = ciphertext[Header::SIZE..].split_at(
                ciphertext.len() - Header::SIZE - <HmacSha256 as OutputSizeUser>::OutputSize::USIZE,
            );
            let mac = HmacSha256Output::clone_from_slice(mac);
            Ok(Self {
                header,
                dk,
                ciphertext,
                mac,
            })
        };
        inner(ciphertext.as_ref(), passphrase.as_ref())
    }

    /// Decrypts the ciphertext into `buf`.
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
    /// # use scryptenc::Decryptor;
    /// #
    /// let data = b"Hello, world!\n";
    /// let ciphertext = include_bytes!("../tests/data/data.txt.enc");
    /// let passphrase = "passphrase";
    ///
    /// let cipher = Decryptor::new(&ciphertext, passphrase).unwrap();
    /// let mut buf = [u8::default(); 14];
    /// cipher.decrypt(&mut buf).unwrap();
    /// # assert_eq!(buf, data.as_slice());
    /// ```
    pub fn decrypt(&self, mut buf: impl AsMut<[u8]>) -> Result<(), Error> {
        let inner = |decryptor: &Self, buf: &mut [u8]| -> Result<(), Error> {
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

            let input = [decryptor.header.as_bytes().as_slice(), decryptor.ciphertext].concat();

            let mut cipher = Aes256Ctr128BE::new(&decryptor.dk.encrypt(), &GenericArray::default());
            cipher
                .apply_keystream_b2b(decryptor.ciphertext, buf)
                .expect("plaintext and ciphertext of the file body should have same lengths");

            verify_mac(&input, &decryptor.dk.mac(), &decryptor.mac)?;

            Ok(())
        };
        inner(self, buf.as_mut())
    }

    /// Decrypts the ciphertext and into a newly allocated `Vec`.
    ///
    /// # Errors
    ///
    /// Returns `Err` if HMAC-SHA-256 at EOF is invalid.
    ///
    /// # Examples
    ///
    /// ```
    /// # use scryptenc::Decryptor;
    /// #
    /// let data = b"Hello, world!\n";
    /// let ciphertext = include_bytes!("../tests/data/data.txt.enc");
    /// let passphrase = "passphrase";
    ///
    /// let cipher = Decryptor::new(&ciphertext, passphrase).unwrap();
    /// let plaintext = cipher.decrypt_to_vec().unwrap();
    /// # assert_eq!(plaintext, data);
    /// ```
    #[cfg(feature = "alloc")]
    pub fn decrypt_to_vec(&self) -> Result<alloc::vec::Vec<u8>, Error> {
        let mut buf = vec![u8::default(); self.out_len()];
        self.decrypt(&mut buf)?;
        Ok(buf)
    }

    /// Returns the number of output bytes of the decrypted data.
    ///
    /// # Examples
    ///
    /// ```
    /// # use scryptenc::Decryptor;
    /// #
    /// let ciphertext = include_bytes!("../tests/data/data.txt.enc");
    /// let passphrase = "passphrase";
    ///
    /// let cipher = Decryptor::new(&ciphertext, passphrase).unwrap();
    /// assert_eq!(cipher.out_len(), 14);
    /// ```
    #[must_use]
    #[inline]
    pub const fn out_len(&self) -> usize {
        self.ciphertext.len()
    }
}
