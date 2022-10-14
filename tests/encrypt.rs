//
// SPDX-License-Identifier: Apache-2.0 OR MIT
//
// Copyright (C) 2022 Shun Sakai
//

// Lint levels of rustc.
#![forbid(unsafe_code)]
#![deny(missing_debug_implementations, missing_docs)]
#![warn(rust_2018_idioms)]
// Lint levels of Clippy.
#![warn(clippy::cargo, clippy::nursery, clippy::pedantic)]

use scrypt::Params;
use scryptenc::Encryptor;
use sha2::{Digest, Sha256};

const PASSWORD: &str = "password";
const DATA: &str = "Hello, world!";

#[test]
fn success() {
    let cipher = Encryptor::with_params(PASSWORD, Params::new(10, 1, 1).unwrap(), DATA);
    let mut buf = vec![u8::default(); cipher.out_len()];
    cipher.encrypt(&mut buf);
    assert_eq!(buf.len(), DATA.len() + 128);

    let encrypted =
        Encryptor::with_params(PASSWORD, Params::new(10, 1, 1).unwrap(), DATA).encrypt_to_vec();
    assert_eq!(encrypted.len(), DATA.len() + 128);
}

#[test]
#[should_panic]
fn invalid_output_length() {
    let cipher = Encryptor::with_params(PASSWORD, Params::new(10, 1, 1).unwrap(), DATA);
    let mut buf = vec![u8::default(); cipher.out_len() - 1];
    cipher.encrypt(&mut buf);
}

#[test]
fn magic_number() {
    let encrypted =
        Encryptor::with_params(PASSWORD, Params::new(10, 1, 1).unwrap(), DATA).encrypt_to_vec();
    assert_eq!(&encrypted[..6], b"scrypt");
}

#[test]
fn version() {
    let encrypted =
        Encryptor::with_params(PASSWORD, Params::new(10, 1, 1).unwrap(), DATA).encrypt_to_vec();
    assert_eq!(encrypted[6], 0);
}

#[test]
fn log_n() {
    let encrypted =
        Encryptor::with_params(PASSWORD, Params::new(10, 1, 1).unwrap(), DATA).encrypt_to_vec();
    assert_eq!(encrypted[7], 10);
}

#[test]
fn r() {
    let encrypted =
        Encryptor::with_params(PASSWORD, Params::new(10, 1, 1).unwrap(), DATA).encrypt_to_vec();
    assert_eq!(&encrypted[8..12], u32::to_be_bytes(1));
}

#[test]
fn p() {
    let encrypted =
        Encryptor::with_params(PASSWORD, Params::new(10, 1, 1).unwrap(), DATA).encrypt_to_vec();
    assert_eq!(&encrypted[12..16], u32::to_be_bytes(1));
}

#[test]
fn checksum() {
    let encrypted =
        Encryptor::with_params(PASSWORD, Params::new(10, 1, 1).unwrap(), DATA).encrypt_to_vec();
    let checksum = Sha256::digest(&encrypted[..48]);
    assert_eq!(&encrypted[48..64], &checksum[..16]);
}

#[test]
fn out_len() {
    let cipher = Encryptor::with_params(PASSWORD, Params::new(10, 1, 1).unwrap(), DATA);
    assert_eq!(cipher.out_len(), 141);
}
