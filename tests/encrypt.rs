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

fn encrypt() -> Encryptor {
    let password = "password";
    let data = "Hello, world!";

    let params = Params::new(10, 1, 1).unwrap();
    Encryptor::with_params(password, params, data)
}

#[test]
fn magic_number() {
    let encrypted = encrypt().encrypt_to_vec();
    assert_eq!(&encrypted[..6], b"scrypt");
}

#[test]
fn version() {
    let encrypted = encrypt().encrypt_to_vec();
    assert_eq!(encrypted[6], 0);
}

#[test]
fn log_n() {
    let encrypted = encrypt().encrypt_to_vec();
    assert_eq!(encrypted[7], 10);
}

#[test]
fn r() {
    let encrypted = encrypt().encrypt_to_vec();
    assert_eq!(&encrypted[8..12], u32::to_be_bytes(1));
}

#[test]
fn p() {
    let encrypted = encrypt().encrypt_to_vec();
    assert_eq!(&encrypted[12..16], u32::to_be_bytes(1));
}

#[test]
fn checksum() {
    let encrypted = encrypt().encrypt_to_vec();
    let checksum = Sha256::digest(&encrypted[..48]);
    assert_eq!(&encrypted[48..64], &checksum[..16]);
}

#[test]
fn out_len() {
    let cipher = encrypt();
    assert_eq!(cipher.out_len(), 141);
}
