// SPDX-FileCopyrightText: 2023 Shun Sakai
//
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! The scrypt parameters.

use crate::{error::Result, format::Header};

/// The scrypt parameters used for the encrypted data.
#[derive(Clone, Copy, Debug)]
pub struct Params(scrypt::Params);

impl Params {
    /// Creates a new instance of the scrypt parameters from `ciphertext`.
    ///
    /// # Errors
    ///
    /// Returns [`Err`] if any of the following are true:
    ///
    /// - `ciphertext` is shorter than 128 bytes.
    /// - The magic number is invalid.
    /// - The version number is the unrecognized scrypt version number.
    /// - The scrypt parameters are invalid.
    ///
    /// # Examples
    ///
    /// ```
    /// # use scryptenc::Params;
    /// #
    /// let ciphertext = include_bytes!("../tests/data/data.txt.enc");
    ///
    /// assert!(Params::new(ciphertext).is_ok());
    /// ```
    pub fn new(ciphertext: impl AsRef<[u8]>) -> Result<Self> {
        let params = Header::parse(ciphertext.as_ref()).map(|h| h.params())?;
        Ok(Self(params))
    }

    /// Gets log2 of the scrypt parameter `N`.
    ///
    /// # Examples
    ///
    /// ```
    /// # use scryptenc::Params;
    /// #
    /// let ciphertext = include_bytes!("../tests/data/data.txt.enc");
    ///
    /// let params = Params::new(ciphertext).unwrap();
    /// assert_eq!(params.log_n(), 10);
    /// ```
    #[must_use]
    #[inline]
    pub fn log_n(&self) -> u8 {
        self.0.log_n()
    }

    /// Gets `N` parameter.
    ///
    /// # Examples
    ///
    /// ```
    /// # use scryptenc::Params;
    /// #
    /// let ciphertext = include_bytes!("../tests/data/data.txt.enc");
    ///
    /// let params = Params::new(ciphertext).unwrap();
    /// assert_eq!(params.n(), 1024);
    /// ```
    #[must_use]
    #[inline]
    pub fn n(&self) -> u64 {
        1 << self.0.log_n()
    }

    /// Gets `r` parameter.
    ///
    /// # Examples
    ///
    /// ```
    /// # use scryptenc::Params;
    /// #
    /// let ciphertext = include_bytes!("../tests/data/data.txt.enc");
    ///
    /// let params = Params::new(ciphertext).unwrap();
    /// assert_eq!(params.r(), 8);
    /// ```
    #[must_use]
    #[inline]
    pub fn r(&self) -> u32 {
        self.0.r()
    }

    /// Gets `p` parameter.
    ///
    /// # Examples
    ///
    /// ```
    /// # use scryptenc::Params;
    /// #
    /// let ciphertext = include_bytes!("../tests/data/data.txt.enc");
    ///
    /// let params = Params::new(ciphertext).unwrap();
    /// assert_eq!(params.p(), 1);
    /// ```
    #[must_use]
    #[inline]
    pub fn p(&self) -> u32 {
        self.0.p()
    }
}
