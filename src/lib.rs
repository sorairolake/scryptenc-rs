// SPDX-FileCopyrightText: 2022 Shun Sakai
//
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! The `scryptenc` crate is an implementation of the scrypt encrypted data
//! format.
//!
//! The format is defined [here][specification-url].
//!
//! # Examples
//!
//! ## Encrypt and decrypt
//!
//! ```
//! # #[cfg(feature = "alloc")]
//! # {
//! use scryptenc::{scrypt::Params, Decryptor, Encryptor};
//!
//! let data = b"Hello, world!";
//! let passphrase = "passphrase";
//!
//! // Encrypt `data` using `passphrase`.
//! let params = Params::new(10, 8, 1, Params::RECOMMENDED_LEN).unwrap();
//! let ciphertext = Encryptor::with_params(data, passphrase, params).encrypt_to_vec();
//! assert_ne!(ciphertext, data);
//!
//! // And decrypt it back.
//! let plaintext = Decryptor::new(&ciphertext, passphrase)
//!     .and_then(|c| c.decrypt_to_vec())
//!     .unwrap();
//! assert_eq!(plaintext, data);
//! # }
//! ```
//!
//! ## Extract the scrypt parameters in the encrypted data
//!
//! ```
//! # #[cfg(feature = "alloc")]
//! # {
//! use scryptenc::{scrypt, Encryptor};
//!
//! let data = b"Hello, world!";
//! let passphrase = "passphrase";
//!
//! // Encrypt `data` using `passphrase`.
//! let ciphertext = Encryptor::new(data, passphrase).encrypt_to_vec();
//!
//! // And extract the scrypt parameters from it.
//! let params = scryptenc::Params::new(ciphertext).unwrap();
//! assert_eq!(params.log_n(), scrypt::Params::RECOMMENDED_LOG_N);
//! assert_eq!(params.n(), 1 << scrypt::Params::RECOMMENDED_LOG_N);
//! assert_eq!(params.r(), scrypt::Params::RECOMMENDED_R);
//! assert_eq!(params.p(), scrypt::Params::RECOMMENDED_P);
//! # }
//! ```
//!
//! [specification-url]: https://github.com/Tarsnap/scrypt/blob/1.3.1/FORMAT

#![doc(html_root_url = "https://docs.rs/scryptenc/0.7.1/")]
#![no_std]
#![cfg_attr(doc_cfg, feature(doc_auto_cfg, doc_cfg))]
// Lint levels of rustc.
#![forbid(unsafe_code)]
#![deny(missing_debug_implementations, missing_docs)]
#![warn(rust_2018_idioms)]
// Lint levels of Clippy.
#![warn(clippy::cargo, clippy::nursery, clippy::pedantic)]

#[cfg(feature = "alloc")]
#[macro_use]
extern crate alloc;
#[cfg(feature = "std")]
extern crate std;

mod decrypt;
mod encrypt;
mod error;
mod format;
mod params;

pub use hmac;
pub use scrypt;

use aes::Aes256;
use ctr::Ctr128BE;
use hmac::{
    digest::{generic_array::GenericArray, typenum::U32, Output},
    Hmac,
};
use sha2::Sha256;

pub use crate::{
    decrypt::Decryptor,
    encrypt::Encryptor,
    error::{Error, Result},
    params::Params,
};

#[cfg(feature = "alloc")]
pub use crate::{
    decrypt::decrypt,
    encrypt::{encrypt, encrypt_with_params},
};

/// A type alias for AES-256-CTR.
type Aes256Ctr128BE = Ctr128BE<Aes256>;

/// A type alias for HMAC-SHA-256.
type HmacSha256 = Hmac<Sha256>;

/// A type alias for output of HMAC-SHA-256.
type HmacSha256Output = Output<HmacSha256>;

/// A type alias for key of HMAC-SHA-256.
type HmacSha256Key = GenericArray<u8, U32>;
