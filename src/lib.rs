//
// SPDX-License-Identifier: Apache-2.0 OR MIT
//
// Copyright (C) 2022 Shun Sakai
//

//! The `scryptenc` crate is an implementation of the scrypt encrypted data
//! format.
//!
//! The format is defined [here][specification-url].
//!
//! # Examples
//!
//! ```
//! use scrypt::Params;
//! use scryptenc::{Decryptor, Encryptor};
//!
//! let password = "password";
//! let data = b"Hello, world!";
//!
//! // Encrypt `data` using `password`.
//! let params = Params::new(10, 8, 1).unwrap();
//! let cipher = Encryptor::with_params(data, password, params);
//! let encrypted = cipher.encrypt_to_vec();
//!
//! // And decrypt it back.
//! let cipher = Decryptor::new(encrypted, password).unwrap();
//! let decrypted = cipher.decrypt_to_vec().unwrap();
//! assert_eq!(decrypted, data);
//! ```
//!
//! [specification-url]: https://github.com/Tarsnap/scrypt/blob/d7a543fb19dca17688e34947aee4558a94200877/FORMAT

#![doc(html_root_url = "https://docs.rs/scryptenc/0.3.1/")]
#![no_std]
#![cfg_attr(doc_cfg, feature(doc_cfg))]
// Lint levels of rustc.
#![forbid(unsafe_code)]
#![deny(missing_debug_implementations, missing_docs)]
#![warn(rust_2018_idioms)]
// Lint levels of Clippy.
#![warn(clippy::cargo, clippy::nursery, clippy::pedantic)]

#[macro_use]
extern crate alloc;
#[cfg(feature = "std")]
extern crate std;

mod decrypt;
mod encrypt;
mod error;
mod format;

pub use crate::{decrypt::Decryptor, encrypt::Encryptor, error::Error, format::Params};
