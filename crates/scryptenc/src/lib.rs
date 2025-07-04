// SPDX-FileCopyrightText: 2022 Shun Sakai
//
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! The `scryptenc` crate is an implementation of the [scrypt encrypted data
//! format].
//!
//! This crate supports version 1 of the scrypt format.
//!
//! # Examples
//!
//! ## Encryption and decryption
//!
//! ```
//! # #[cfg(feature = "alloc")]
//! # {
//! use scryptenc::{Decryptor, Encryptor, scrypt::Params};
//!
//! let data = b"Hello, world!\n";
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
//! ### `no_std` support
//!
//! This crate supports `no_std` mode and can be used without the `alloc` crate
//! and the `std` crate. Disables the `default` feature to enable this.
//!
//! ```
//! use scryptenc::{Decryptor, Encryptor, scrypt::Params};
//!
//! let data = b"Hello, world!\n";
//! let passphrase = "passphrase";
//!
//! // Encrypt `data` using `passphrase`.
//! let params = Params::new(10, 8, 1, Params::RECOMMENDED_LEN).unwrap();
//! let cipher = Encryptor::with_params(data, passphrase, params);
//! let mut buf = [u8::default(); 142];
//! cipher.encrypt(&mut buf);
//! assert_ne!(buf.as_slice(), data);
//!
//! // And decrypt it back.
//! let cipher = Decryptor::new(&buf, passphrase).unwrap();
//! let mut buf = [u8::default(); 14];
//! cipher.decrypt(&mut buf).unwrap();
//! assert_eq!(buf, *data);
//! ```
//!
//! ## Extracting the scrypt parameters in the encrypted data
//!
//! ```
//! # #[cfg(feature = "alloc")]
//! # {
//! use scryptenc::{Encryptor, scrypt};
//!
//! let data = b"Hello, world!\n";
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
//! [scrypt encrypted data format]: https://github.com/Tarsnap/scrypt/blob/1.3.3/FORMAT

#![doc(html_root_url = "https://docs.rs/scryptenc/0.9.10/")]
#![no_std]
#![cfg_attr(docsrs, feature(doc_auto_cfg, doc_cfg))]
// Lint levels of rustc.
#![deny(missing_docs)]

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

use aes::Aes256;
use ctr::Ctr128BE;
pub use hmac;
use hmac::{
    Hmac,
    digest::{Output, generic_array::GenericArray, typenum::U32},
};
pub use scrypt;
use sha2::Sha256;

pub use crate::{
    decrypt::Decryptor,
    encrypt::Encryptor,
    error::{Error, Result},
    format::{HEADER_SIZE, TAG_SIZE},
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
