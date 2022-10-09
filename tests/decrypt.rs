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

use hmac::digest::MacError;
use scrypt::errors::InvalidParams;
use scryptenc::{Decryptor, Error};

const PASSWORD: &[u8] = b"password";
const TEST_DATA: &[u8] = include_bytes!("data/data.txt");
// Generated using `scrypt` version 1.3.1.
const TEST_DATA_ENC: &[u8] = include_bytes!("data/data.txt.enc");

fn decrypt(password: &[u8], data: &[u8]) -> Result<Vec<u8>, Error> {
    let cipher = Decryptor::new(password, data)?;
    cipher.decrypt_to_vec()
}

#[test]
fn success() {
    let decrypted = decrypt(PASSWORD, TEST_DATA_ENC).unwrap();
    assert_eq!(decrypted, TEST_DATA);
}

#[test]
fn incorrect_password() {
    let decrypted = decrypt(b"passphrase", TEST_DATA_ENC).unwrap_err();
    assert_eq!(
        decrypted.to_string(),
        Error::InvalidSignature(MacError).to_string()
    );
}

#[test]
fn invalid_length() {
    let data: [u8; 127] = [u8::default(); 127];
    let decrypted = decrypt(PASSWORD, &data).unwrap_err();
    assert_eq!(decrypted.to_string(), Error::InvalidLength(127).to_string());
}

#[test]
fn invalid_magic_number() {
    let mut data = TEST_DATA_ENC.to_vec();
    data[0] = 'b'.try_into().unwrap();
    let decrypted = decrypt(PASSWORD, &data).unwrap_err();
    assert_eq!(decrypted.to_string(), Error::InvalidMagicNumber.to_string());
}

#[test]
fn unknown_version() {
    let mut data = TEST_DATA_ENC.to_vec();
    data[6] = 1;
    let decrypted = decrypt(PASSWORD, &data).unwrap_err();
    assert_eq!(decrypted.to_string(), Error::UnknownVersion(1).to_string());
}

#[test]
fn invalid_params() {
    let data = TEST_DATA_ENC.to_vec();

    let mut data_1 = data.clone();
    data_1[7] = 65;
    let decrypted = decrypt(PASSWORD, &data_1).unwrap_err();
    assert_eq!(
        decrypted.to_string(),
        Error::InvalidParams(InvalidParams).to_string()
    );

    let mut data_2 = data.clone();
    data_2[8..12].copy_from_slice(&u32::to_be_bytes(0));
    let decrypted = decrypt(PASSWORD, &data_2).unwrap_err();
    assert_eq!(
        decrypted.to_string(),
        Error::InvalidParams(InvalidParams).to_string()
    );

    let mut data_3 = data;
    data_3[12..16].copy_from_slice(&u32::to_be_bytes(0));
    let decrypted = decrypt(PASSWORD, &data_3).unwrap_err();
    assert_eq!(
        decrypted.to_string(),
        Error::InvalidParams(InvalidParams).to_string()
    );
}

#[test]
fn invalid_checksum() {
    let mut data = TEST_DATA_ENC.to_vec();
    let mut checksum: [u8; 16] = data[48..64].try_into().unwrap();
    checksum.reverse();
    data[48..64].copy_from_slice(&checksum);
    let decrypted = decrypt(PASSWORD, &data).unwrap_err();
    assert_eq!(decrypted.to_string(), Error::InvalidChecksum.to_string());
}

#[test]
fn invalid_signature() {
    let mut data = TEST_DATA_ENC.to_vec();
    let mut signature: [u8; 32] = data[64..96].try_into().unwrap();
    signature.reverse();
    data[64..96].copy_from_slice(&signature);
    let decrypted = decrypt(PASSWORD, &data).unwrap_err();
    assert_eq!(
        decrypted.to_string(),
        Error::InvalidSignature(MacError).to_string()
    );
}
