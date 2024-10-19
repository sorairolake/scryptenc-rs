// SPDX-FileCopyrightText: 2022 Shun Sakai
//
// SPDX-License-Identifier: Apache-2.0 OR MIT

// Lint levels of rustc.
#![forbid(unsafe_code)]
#![deny(missing_debug_implementations)]
#![warn(rust_2018_idioms)]
// Lint levels of Clippy.
#![warn(clippy::cargo, clippy::nursery, clippy::pedantic)]

use scryptenc::{scrypt::Params, Decryptor, Encryptor, HEADER_SIZE, TAG_SIZE};
use sha2::{Digest, Sha256};

const PASSPHRASE: &str = "passphrase";
const TEST_DATA: &[u8] = include_bytes!("data/data.txt");

#[test]
fn success() {
    let cipher = Encryptor::new(&TEST_DATA, PASSPHRASE);
    let mut buf = [u8::default(); TEST_DATA.len() + HEADER_SIZE + TAG_SIZE];
    cipher.encrypt(&mut buf);
    assert_ne!(buf, TEST_DATA);
    assert_eq!(buf.len(), TEST_DATA.len() + HEADER_SIZE + TAG_SIZE);

    let params = scryptenc::Params::new(buf).unwrap();
    assert_eq!(params.log_n(), 17);
    assert_eq!(params.r(), 8);
    assert_eq!(params.p(), 1);

    let cipher = Decryptor::new(&buf, PASSPHRASE).unwrap();
    let mut buf = [u8::default(); TEST_DATA.len()];
    cipher.decrypt(&mut buf).unwrap();
    assert_eq!(buf, TEST_DATA);
}

#[test]
fn success_with_params() {
    let cipher = Encryptor::with_params(
        &TEST_DATA,
        PASSPHRASE,
        Params::new(4, 10, 16, Params::RECOMMENDED_LEN).unwrap(),
    );
    let mut buf = [u8::default(); TEST_DATA.len() + HEADER_SIZE + TAG_SIZE];
    cipher.encrypt(&mut buf);
    assert_ne!(buf, TEST_DATA);
    assert_eq!(buf.len(), TEST_DATA.len() + HEADER_SIZE + TAG_SIZE);

    let params = scryptenc::Params::new(buf).unwrap();
    assert_eq!(params.log_n(), 4);
    assert_eq!(params.r(), 10);
    assert_eq!(params.p(), 16);

    let cipher = Decryptor::new(&buf, PASSPHRASE).unwrap();
    let mut buf = [u8::default(); TEST_DATA.len()];
    cipher.decrypt(&mut buf).unwrap();
    assert_eq!(buf, TEST_DATA);
}

#[cfg(feature = "alloc")]
#[test]
fn success_to_vec() {
    let ciphertext = Encryptor::with_params(
        &TEST_DATA,
        PASSPHRASE,
        Params::new(4, 10, 16, Params::RECOMMENDED_LEN).unwrap(),
    )
    .encrypt_to_vec();
    assert_ne!(ciphertext, TEST_DATA);
    assert_eq!(ciphertext.len(), TEST_DATA.len() + HEADER_SIZE + TAG_SIZE);

    let params = scryptenc::Params::new(&ciphertext).unwrap();
    assert_eq!(params.log_n(), 4);
    assert_eq!(params.r(), 10);
    assert_eq!(params.p(), 16);

    let plaintext = Decryptor::new(&ciphertext, PASSPHRASE)
        .and_then(|c| c.decrypt_to_vec())
        .unwrap();
    assert_eq!(plaintext, TEST_DATA);
}

#[test]
#[should_panic(expected = "source slice length (32) does not match destination slice length (31)")]
fn invalid_output_length() {
    let cipher = Encryptor::with_params(
        &TEST_DATA,
        PASSPHRASE,
        Params::new(4, 10, 16, Params::RECOMMENDED_LEN).unwrap(),
    );
    let mut buf = [u8::default(); TEST_DATA.len() + HEADER_SIZE + TAG_SIZE - 1];
    cipher.encrypt(&mut buf);
}

#[test]
fn magic_number() {
    let cipher = Encryptor::with_params(
        &TEST_DATA,
        PASSPHRASE,
        Params::new(4, 10, 16, Params::RECOMMENDED_LEN).unwrap(),
    );
    let mut buf = [u8::default(); TEST_DATA.len() + HEADER_SIZE + TAG_SIZE];
    cipher.encrypt(&mut buf);
    assert_eq!(&buf[..6], b"scrypt");
}

#[test]
fn version() {
    let cipher = Encryptor::with_params(
        &TEST_DATA,
        PASSPHRASE,
        Params::new(4, 10, 16, Params::RECOMMENDED_LEN).unwrap(),
    );
    let mut buf = [u8::default(); TEST_DATA.len() + HEADER_SIZE + TAG_SIZE];
    cipher.encrypt(&mut buf);
    assert_eq!(buf[6], 0);
}

#[test]
fn log_n() {
    let cipher = Encryptor::with_params(
        &TEST_DATA,
        PASSPHRASE,
        Params::new(4, 10, 16, Params::RECOMMENDED_LEN).unwrap(),
    );
    let mut buf = [u8::default(); TEST_DATA.len() + HEADER_SIZE + TAG_SIZE];
    cipher.encrypt(&mut buf);
    assert_eq!(buf[7], 4);
}

#[test]
fn r() {
    let cipher = Encryptor::with_params(
        &TEST_DATA,
        PASSPHRASE,
        Params::new(4, 10, 16, Params::RECOMMENDED_LEN).unwrap(),
    );
    let mut buf = [u8::default(); TEST_DATA.len() + HEADER_SIZE + TAG_SIZE];
    cipher.encrypt(&mut buf);
    assert_eq!(&buf[8..12], u32::to_be_bytes(10));
}

#[test]
fn p() {
    let cipher = Encryptor::with_params(
        &TEST_DATA,
        PASSPHRASE,
        Params::new(4, 10, 16, Params::RECOMMENDED_LEN).unwrap(),
    );
    let mut buf = [u8::default(); TEST_DATA.len() + HEADER_SIZE + TAG_SIZE];
    cipher.encrypt(&mut buf);
    assert_eq!(&buf[12..16], u32::to_be_bytes(16));
}

#[test]
fn checksum() {
    let cipher = Encryptor::with_params(
        &TEST_DATA,
        PASSPHRASE,
        Params::new(4, 10, 16, Params::RECOMMENDED_LEN).unwrap(),
    );
    let mut buf = [u8::default(); TEST_DATA.len() + HEADER_SIZE + TAG_SIZE];
    cipher.encrypt(&mut buf);
    let checksum = Sha256::digest(&buf[..48]);
    assert_eq!(&buf[48..64], &checksum[..16]);
}

#[test]
fn out_len() {
    let cipher = Encryptor::with_params(
        &TEST_DATA,
        PASSPHRASE,
        Params::new(4, 10, 16, Params::RECOMMENDED_LEN).unwrap(),
    );
    assert_eq!(cipher.out_len(), TEST_DATA.len() + HEADER_SIZE + TAG_SIZE);
}

#[cfg(feature = "alloc")]
#[test]
fn success_convenience_function() {
    let ciphertext = scryptenc::encrypt(TEST_DATA, PASSPHRASE);
    assert_ne!(ciphertext, TEST_DATA);
    assert_eq!(ciphertext.len(), TEST_DATA.len() + HEADER_SIZE + TAG_SIZE);

    let params = scryptenc::Params::new(&ciphertext).unwrap();
    assert_eq!(params.log_n(), 17);
    assert_eq!(params.r(), 8);
    assert_eq!(params.p(), 1);

    let plaintext = scryptenc::decrypt(ciphertext, PASSPHRASE).unwrap();
    assert_eq!(plaintext, TEST_DATA);
}

#[cfg(feature = "alloc")]
#[test]
fn success_convenience_function_with_params() {
    let ciphertext = scryptenc::encrypt_with_params(
        TEST_DATA,
        PASSPHRASE,
        Params::new(4, 10, 16, Params::RECOMMENDED_LEN).unwrap(),
    );
    assert_ne!(ciphertext, TEST_DATA);
    assert_eq!(ciphertext.len(), TEST_DATA.len() + HEADER_SIZE + TAG_SIZE);

    let params = scryptenc::Params::new(&ciphertext).unwrap();
    assert_eq!(params.log_n(), 4);
    assert_eq!(params.r(), 10);
    assert_eq!(params.p(), 16);

    let plaintext = scryptenc::decrypt(ciphertext, PASSPHRASE).unwrap();
    assert_eq!(plaintext, TEST_DATA);
}
