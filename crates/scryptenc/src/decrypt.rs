// SPDX-FileCopyrightText: 2022 Shun Sakai
//
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! Decrypts from the scrypt encrypted data format.

use aes::cipher::{generic_array::GenericArray, KeyIvInit, StreamCipher};
use hmac::Mac;

use crate::{
    format::{DerivedKey, Header},
    Aes256Ctr128BE, Error, HmacSha256, HmacSha256Key, HmacSha256Output, Result, HEADER_SIZE,
    TAG_SIZE,
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
    /// Returns [`Err`] if any of the following are true:
    ///
    /// - `ciphertext` is shorter than 128 bytes.
    /// - The magic number is invalid.
    /// - The version number is the unrecognized scrypt version number.
    /// - The scrypt parameters are invalid.
    /// - The checksum of the header mismatch.
    /// - The MAC (authentication tag) of the header is invalid.
    ///
    /// # Examples
    ///
    /// ```
    /// # use scryptenc::Decryptor;
    /// #
    /// let ciphertext = include_bytes!("../tests/data/data.txt.scrypt");
    /// let passphrase = "passphrase";
    ///
    /// let cipher = Decryptor::new(&ciphertext, passphrase).unwrap();
    /// ```
    pub fn new(ciphertext: &'c impl AsRef<[u8]>, passphrase: impl AsRef<[u8]>) -> Result<Self> {
        let inner = |ciphertext: &'c [u8], passphrase: &[u8]| -> Result<Self> {
            let mut header = Header::parse(ciphertext)?;
            header.verify_checksum(&ciphertext[48..64])?;

            // The derived key size is 64 bytes. The first 256 bits are for AES-256-CTR key,
            // and the last 256 bits are for HMAC-SHA-256 key.
            let mut dk = [u8::default(); DerivedKey::SIZE];
            scrypt::scrypt(passphrase, &header.salt(), &header.params().into(), &mut dk)
                .expect("derived key size should be 64 bytes");
            let dk = DerivedKey::new(dk);

            header.verify_mac(&dk.mac(), ciphertext[64..HEADER_SIZE].into())?;
            let (ciphertext, mac) =
                ciphertext[HEADER_SIZE..].split_at(ciphertext.len() - HEADER_SIZE - TAG_SIZE);
            let mac = *HmacSha256Output::from_slice(mac);
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
    /// Returns [`Err`] if the MAC (authentication tag) of the scrypt encrypted
    /// data format is invalid.
    ///
    /// # Panics
    ///
    /// Panics if any of the following are true:
    ///
    /// - `buf` and the decrypted data have different lengths.
    /// - The end of the keystream will be reached with the given data length.
    ///
    /// # Examples
    ///
    /// ```
    /// # use scryptenc::Decryptor;
    /// #
    /// let data = b"Hello, world!\n";
    /// let ciphertext = include_bytes!("../tests/data/data.txt.scrypt");
    /// let passphrase = "passphrase";
    ///
    /// let cipher = Decryptor::new(&ciphertext, passphrase).unwrap();
    /// let mut buf = [u8::default(); 14];
    /// cipher.decrypt(&mut buf).unwrap();
    /// # assert_eq!(buf, data.as_slice());
    /// ```
    pub fn decrypt(&self, mut buf: impl AsMut<[u8]>) -> Result<()> {
        let inner = |decryptor: &Self, buf: &mut [u8]| -> Result<()> {
            fn verify_mac(data: &[u8], key: &HmacSha256Key, tag: &HmacSha256Output) -> Result<()> {
                let mut mac = HmacSha256::new_from_slice(key)
                    .expect("HMAC-SHA-256 key size should be 256 bits");
                mac.update(data);
                mac.verify(tag).map_err(Error::InvalidMac)
            }

            buf.copy_from_slice(decryptor.ciphertext);

            let mut cipher = Aes256Ctr128BE::new(&decryptor.dk.encrypt(), &GenericArray::default());
            cipher.apply_keystream(buf);
            let data = [&decryptor.header.as_bytes(), decryptor.ciphertext].concat();
            verify_mac(&data, &decryptor.dk.mac(), &decryptor.mac)
        };
        inner(self, buf.as_mut())
    }

    /// Decrypts the ciphertext and into a newly allocated
    /// [`Vec`](alloc::vec::Vec).
    ///
    /// # Errors
    ///
    /// Returns [`Err`] if the MAC (authentication tag) of the scrypt encrypted
    /// data format is invalid.
    ///
    /// # Examples
    ///
    /// ```
    /// # use scryptenc::Decryptor;
    /// #
    /// let data = b"Hello, world!\n";
    /// let ciphertext = include_bytes!("../tests/data/data.txt.scrypt");
    /// let passphrase = "passphrase";
    ///
    /// let cipher = Decryptor::new(&ciphertext, passphrase).unwrap();
    /// let plaintext = cipher.decrypt_to_vec().unwrap();
    /// # assert_eq!(plaintext, data);
    /// ```
    #[cfg(feature = "alloc")]
    pub fn decrypt_to_vec(&self) -> Result<alloc::vec::Vec<u8>> {
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
    /// let ciphertext = include_bytes!("../tests/data/data.txt.scrypt");
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

/// Decrypts `ciphertext` and into a newly allocated [`Vec`](alloc::vec::Vec).
///
/// This is a convenience function for using [`Decryptor::new`] and
/// [`Decryptor::decrypt_to_vec`].
///
/// # Errors
///
/// Returns [`Err`] if any of the following are true:
///
/// - `ciphertext` is shorter than 128 bytes.
/// - The magic number is invalid.
/// - The version number is the unrecognized scrypt version number.
/// - The scrypt parameters are invalid.
/// - The checksum of the header mismatch.
/// - The MAC (authentication tag) of the header is invalid.
/// - The MAC (authentication tag) of the scrypt encrypted data format is
///   invalid.
///
/// # Examples
///
/// ```
/// let data = b"Hello, world!\n";
/// let ciphertext = include_bytes!("../tests/data/data.txt.scrypt");
/// let passphrase = "passphrase";
///
/// let plaintext = scryptenc::decrypt(ciphertext, passphrase).unwrap();
/// # assert_eq!(plaintext, data);
/// ```
#[cfg(feature = "alloc")]
pub fn decrypt(
    ciphertext: impl AsRef<[u8]>,
    passphrase: impl AsRef<[u8]>,
) -> Result<alloc::vec::Vec<u8>> {
    Decryptor::new(&ciphertext, passphrase).and_then(|c| c.decrypt_to_vec())
}
