// SPDX-FileCopyrightText: 2022 Shun Sakai
//
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! Encrypts to the scrypt encrypted data format.

use aes::cipher::{generic_array::GenericArray, KeyIvInit, StreamCipher};
use hmac::Mac;
use scrypt::Params;

use crate::{
    format::{DerivedKey, Header},
    Aes256Ctr128BE, HmacSha256, HmacSha256Key, HmacSha256Output, HEADER_SIZE, TAG_SIZE,
};

/// Encryptor for the scrypt encrypted data format.
#[derive(Clone, Debug)]
pub struct Encryptor<'m> {
    header: Header,
    dk: DerivedKey,
    plaintext: &'m [u8],
}

impl<'m> Encryptor<'m> {
    /// Creates a new `Encryptor`.
    ///
    /// This uses the [recommended scrypt parameters] created by
    /// [`Params::default`] which are sufficient for most use-cases.
    ///
    /// # Examples
    ///
    /// ```
    /// # use scryptenc::Encryptor;
    /// #
    /// let data = b"Hello, world!\n";
    /// let passphrase = "passphrase";
    ///
    /// let cipher = Encryptor::new(data, passphrase);
    /// ```
    ///
    /// [recommended scrypt parameters]: https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html
    pub fn new(plaintext: &'m impl AsRef<[u8]>, passphrase: impl AsRef<[u8]>) -> Self {
        Self::with_params(plaintext, passphrase, Params::default())
    }

    #[allow(clippy::missing_panics_doc)]
    /// Creates a new `Encryptor` with the specified [`Params`].
    ///
    /// # Examples
    ///
    /// ```
    /// # use scryptenc::{scrypt::Params, Encryptor};
    /// #
    /// let data = b"Hello, world!\n";
    /// let passphrase = "passphrase";
    ///
    /// let params = Params::new(10, 8, 1, Params::RECOMMENDED_LEN).unwrap();
    /// let cipher = Encryptor::with_params(data, passphrase, params);
    /// ```
    pub fn with_params(
        plaintext: &'m impl AsRef<[u8]>,
        passphrase: impl AsRef<[u8]>,
        params: Params,
    ) -> Self {
        let inner = |plaintext: &'m [u8], passphrase: &[u8], params: Params| -> Self {
            let mut header = Header::new(params);

            // The derived key size is 64 bytes. The first 256 bits are for AES-256-CTR key,
            // and the last 256 bits are for HMAC-SHA-256 key.
            let mut dk = [u8::default(); DerivedKey::SIZE];
            scrypt::scrypt(passphrase, &header.salt(), &header.params().into(), &mut dk)
                .expect("derived key size should be 64 bytes");
            let dk = DerivedKey::new(dk);

            header.compute_checksum();
            header.compute_mac(&dk.mac());
            Self {
                header,
                dk,
                plaintext,
            }
        };
        inner(plaintext.as_ref(), passphrase.as_ref(), params)
    }

    /// Encrypts the plaintext into `buf`.
    ///
    /// # Panics
    ///
    /// Panics if any of the following are true:
    ///
    /// - `buf` and the encrypted data have different lengths.
    /// - The end of the keystream will be reached with the given data length.
    ///
    /// # Examples
    ///
    /// ```
    /// # use scryptenc::{scrypt::Params, Encryptor};
    /// #
    /// let data = b"Hello, world!\n";
    /// let passphrase = "passphrase";
    ///
    /// let params = Params::new(10, 8, 1, Params::RECOMMENDED_LEN).unwrap();
    /// let cipher = Encryptor::with_params(data, passphrase, params);
    /// let mut buf = [u8::default(); 142];
    /// cipher.encrypt(&mut buf);
    /// # assert_ne!(buf, data.as_slice());
    /// ```
    pub fn encrypt(&self, mut buf: impl AsMut<[u8]>) {
        let inner = |encryptor: &Self, buf: &mut [u8]| {
            fn compute_mac(data: &[u8], key: &HmacSha256Key) -> HmacSha256Output {
                let mut mac = HmacSha256::new_from_slice(key)
                    .expect("HMAC-SHA-256 key size should be 256 bits");
                mac.update(data);
                mac.finalize().into_bytes()
            }

            let bound = (HEADER_SIZE, encryptor.out_len() - TAG_SIZE);
            buf[..bound.0].copy_from_slice(&encryptor.header.as_bytes());
            let body = &mut buf[bound.0..bound.1];
            body.copy_from_slice(encryptor.plaintext);

            let mut cipher = Aes256Ctr128BE::new(&encryptor.dk.encrypt(), &GenericArray::default());
            cipher.apply_keystream(body);
            let mac = compute_mac(&buf[..bound.1], &encryptor.dk.mac());
            buf[bound.1..].copy_from_slice(&mac);
        };
        inner(self, buf.as_mut());
    }

    /// Encrypts the plaintext and into a newly allocated
    /// [`Vec`](alloc::vec::Vec).
    ///
    /// # Examples
    ///
    /// ```
    /// # use scryptenc::{scrypt::Params, Encryptor};
    /// #
    /// let data = b"Hello, world!\n";
    /// let passphrase = "passphrase";
    ///
    /// let params = Params::new(10, 8, 1, Params::RECOMMENDED_LEN).unwrap();
    /// let cipher = Encryptor::with_params(data, passphrase, params);
    /// let ciphertext = cipher.encrypt_to_vec();
    /// # assert_ne!(ciphertext, data);
    /// ```
    #[cfg(feature = "alloc")]
    #[must_use]
    pub fn encrypt_to_vec(&self) -> alloc::vec::Vec<u8> {
        let mut buf = vec![u8::default(); self.out_len()];
        self.encrypt(&mut buf);
        buf
    }

    #[allow(clippy::missing_panics_doc)]
    /// Returns the number of output bytes of the encrypted data.
    ///
    /// # Examples
    ///
    /// ```
    /// # use scryptenc::{scrypt::Params, Encryptor};
    /// #
    /// let data = b"Hello, world!\n";
    /// let passphrase = "passphrase";
    ///
    /// let params = Params::new(10, 8, 1, Params::RECOMMENDED_LEN).unwrap();
    /// let cipher = Encryptor::with_params(data, passphrase, params);
    /// assert_eq!(cipher.out_len(), 142);
    /// ```
    #[must_use]
    #[inline]
    pub const fn out_len(&self) -> usize {
        assert!(self.plaintext.len() <= (usize::MAX - HEADER_SIZE - TAG_SIZE));
        HEADER_SIZE + self.plaintext.len() + TAG_SIZE
    }
}

/// Encrypts `plaintext` and into a newly allocated [`Vec`](alloc::vec::Vec).
///
/// This uses the [recommended scrypt parameters] created by [`Params::default`]
/// which are sufficient for most use-cases.
///
/// This is a convenience function for using [`Encryptor::new`] and
/// [`Encryptor::encrypt_to_vec`].
///
/// # Examples
///
/// ```
/// let data = b"Hello, world!\n";
/// let passphrase = "passphrase";
///
/// let ciphertext = scryptenc::encrypt(data, passphrase);
/// # assert_ne!(ciphertext, data);
/// ```
///
/// [recommended scrypt parameters]: https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html
#[cfg(feature = "alloc")]
pub fn encrypt(plaintext: impl AsRef<[u8]>, passphrase: impl AsRef<[u8]>) -> alloc::vec::Vec<u8> {
    Encryptor::new(&plaintext, passphrase).encrypt_to_vec()
}

#[allow(clippy::module_name_repetitions)]
/// Encrypts `plaintext` with the specified [`Params`] and into a newly
/// allocated [`Vec`](alloc::vec::Vec).
///
/// This is a convenience function for using [`Encryptor::with_params`] and
/// [`Encryptor::encrypt_to_vec`].
///
/// # Examples
///
/// ```
/// # use scryptenc::scrypt::Params;
/// #
/// let data = b"Hello, world!\n";
/// let passphrase = "passphrase";
///
/// let params = Params::new(10, 8, 1, Params::RECOMMENDED_LEN).unwrap();
/// let ciphertext = scryptenc::encrypt_with_params(data, passphrase, params);
/// # assert_ne!(ciphertext, data);
/// ```
#[cfg(feature = "alloc")]
pub fn encrypt_with_params(
    plaintext: impl AsRef<[u8]>,
    passphrase: impl AsRef<[u8]>,
    params: Params,
) -> alloc::vec::Vec<u8> {
    Encryptor::with_params(&plaintext, passphrase, params).encrypt_to_vec()
}
