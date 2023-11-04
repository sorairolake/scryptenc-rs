// SPDX-FileCopyrightText: 2023 Shun Sakai
//
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! The scrypt parameters.

use crate::{error::Result, format::Header};

/// The scrypt parameters used for the encrypted data.
#[derive(Clone, Copy, Debug)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub struct Params {
    #[cfg_attr(feature = "serde", serde(rename = "logN"))]
    log_n: u8,
    r: u32,
    p: u32,
}

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
    /// let ciphertext = include_bytes!("../tests/data/data.txt.scrypt");
    ///
    /// assert!(Params::new(ciphertext).is_ok());
    /// ```
    pub fn new(ciphertext: impl AsRef<[u8]>) -> Result<Self> {
        let params = Header::parse(ciphertext.as_ref()).map(|h| h.params())?;
        Ok(params)
    }

    /// Gets log2 of the scrypt parameter `N`.
    ///
    /// # Examples
    ///
    /// ```
    /// # use scryptenc::Params;
    /// #
    /// let ciphertext = include_bytes!("../tests/data/data.txt.scrypt");
    ///
    /// let params = Params::new(ciphertext).unwrap();
    /// assert_eq!(params.log_n(), 10);
    /// ```
    #[must_use]
    #[inline]
    pub const fn log_n(&self) -> u8 {
        self.log_n
    }

    /// Gets `N` parameter.
    ///
    /// # Examples
    ///
    /// ```
    /// # use scryptenc::Params;
    /// #
    /// let ciphertext = include_bytes!("../tests/data/data.txt.scrypt");
    ///
    /// let params = Params::new(ciphertext).unwrap();
    /// assert_eq!(params.n(), 1024);
    /// ```
    #[must_use]
    #[inline]
    pub const fn n(&self) -> u64 {
        1 << self.log_n
    }

    /// Gets `r` parameter.
    ///
    /// # Examples
    ///
    /// ```
    /// # use scryptenc::Params;
    /// #
    /// let ciphertext = include_bytes!("../tests/data/data.txt.scrypt");
    ///
    /// let params = Params::new(ciphertext).unwrap();
    /// assert_eq!(params.r(), 8);
    /// ```
    #[must_use]
    #[inline]
    pub const fn r(&self) -> u32 {
        self.r
    }

    /// Gets `p` parameter.
    ///
    /// # Examples
    ///
    /// ```
    /// # use scryptenc::Params;
    /// #
    /// let ciphertext = include_bytes!("../tests/data/data.txt.scrypt");
    ///
    /// let params = Params::new(ciphertext).unwrap();
    /// assert_eq!(params.p(), 1);
    /// ```
    #[must_use]
    #[inline]
    pub const fn p(&self) -> u32 {
        self.p
    }
}

impl From<Params> for scrypt::Params {
    fn from(params: Params) -> Self {
        Self::new(
            params.log_n(),
            params.r(),
            params.p(),
            Self::RECOMMENDED_LEN,
        )
        .expect("`Params` should be valid as `scrypt::Params`")
    }
}

impl From<scrypt::Params> for Params {
    fn from(params: scrypt::Params) -> Self {
        let (log_n, r, p) = (params.log_n(), params.r(), params.p());
        Self { log_n, r, p }
    }
}
