// SPDX-FileCopyrightText: 2022 Shun Sakai
//
// SPDX-License-Identifier: Apache-2.0 OR MIT

// Lint levels of rustc.
#![forbid(unsafe_code)]
#![deny(missing_debug_implementations, missing_docs)]
#![warn(rust_2018_idioms)]
// Lint levels of Clippy.
#![warn(clippy::cargo, clippy::nursery, clippy::pedantic)]

use scryptenc::{hmac::digest::MacError, scrypt::errors::InvalidParams, Decryptor, Error};

const PASSPHRASE: &str = "passphrase";
const TEST_DATA: &[u8] = include_bytes!("data/data.txt");
// Generated using `scrypt` version 1.3.1.
const TEST_DATA_ENC: &[u8] = include_bytes!("data/data.txt.enc");

#[test]
fn success() {
    {
        let cipher = Decryptor::new(&TEST_DATA_ENC, PASSPHRASE).unwrap();
        let mut buf = vec![u8::default(); cipher.out_len()];
        cipher.decrypt(&mut buf).unwrap();
        assert_eq!(buf, TEST_DATA);
    }

    {
        let plaintext = Decryptor::new(&TEST_DATA_ENC, PASSPHRASE)
            .and_then(Decryptor::decrypt_to_vec)
            .unwrap();
        assert_eq!(plaintext, TEST_DATA);
    }
}

#[test]
#[should_panic(expected = "plaintext and ciphertext of the file body should have same lengths")]
fn invalid_output_length() {
    let cipher = Decryptor::new(&TEST_DATA_ENC, PASSPHRASE).unwrap();
    let mut buf = vec![u8::default(); cipher.out_len() + 1];
    cipher.decrypt(&mut buf).unwrap();
}

#[test]
fn incorrect_passphrase() {
    let plaintext = Decryptor::new(&TEST_DATA_ENC, "password")
        .and_then(Decryptor::decrypt_to_vec)
        .unwrap_err();
    assert_eq!(plaintext, Error::InvalidHeaderMac(MacError));
}

#[test]
fn invalid_length() {
    let data = [u8::default(); 127];
    let plaintext = Decryptor::new(&data, PASSPHRASE)
        .and_then(Decryptor::decrypt_to_vec)
        .unwrap_err();
    assert_eq!(plaintext, Error::InvalidLength);
}

#[test]
fn invalid_magic_number() {
    let mut data: [u8; 142] = TEST_DATA_ENC.try_into().unwrap();
    data[0] = u32::from('b').try_into().unwrap();
    let plaintext = Decryptor::new(&data, PASSPHRASE)
        .and_then(Decryptor::decrypt_to_vec)
        .unwrap_err();
    assert_eq!(plaintext, Error::InvalidMagicNumber);
}

#[test]
fn unknown_version() {
    let mut data: [u8; 142] = TEST_DATA_ENC.try_into().unwrap();
    data[6] = 1;
    let plaintext = Decryptor::new(&data, PASSPHRASE)
        .and_then(Decryptor::decrypt_to_vec)
        .unwrap_err();
    assert_eq!(plaintext, Error::UnknownVersion(1));
}

#[test]
fn invalid_params() {
    let mut data: [u8; 142] = TEST_DATA_ENC.try_into().unwrap();

    {
        data[7] = 65;
        let plaintext = Decryptor::new(&data, PASSPHRASE)
            .and_then(Decryptor::decrypt_to_vec)
            .unwrap_err();
        assert_eq!(plaintext, Error::InvalidParams(InvalidParams));
    }

    {
        data[8..12].copy_from_slice(&u32::to_be_bytes(0));
        let plaintext = Decryptor::new(&data, PASSPHRASE)
            .and_then(Decryptor::decrypt_to_vec)
            .unwrap_err();
        assert_eq!(plaintext, Error::InvalidParams(InvalidParams));
    }

    {
        data[12..16].copy_from_slice(&u32::to_be_bytes(0));
        let plaintext = Decryptor::new(&data, PASSPHRASE)
            .and_then(Decryptor::decrypt_to_vec)
            .unwrap_err();
        assert_eq!(plaintext, Error::InvalidParams(InvalidParams));
    }
}

#[test]
fn invalid_checksum() {
    let mut data: [u8; 142] = TEST_DATA_ENC.try_into().unwrap();
    let mut checksum: [u8; 16] = data[48..64].try_into().unwrap();
    checksum.reverse();
    data[48..64].copy_from_slice(&checksum);
    let plaintext = Decryptor::new(&data, PASSPHRASE)
        .and_then(Decryptor::decrypt_to_vec)
        .unwrap_err();
    assert_eq!(plaintext, Error::InvalidChecksum);
}

#[test]
fn invalid_header_mac() {
    let mut data: [u8; 142] = TEST_DATA_ENC.try_into().unwrap();
    let mut header_mac: [u8; 32] = data[64..96].try_into().unwrap();
    header_mac.reverse();
    data[64..96].copy_from_slice(&header_mac);
    let plaintext = Decryptor::new(&data, PASSPHRASE)
        .and_then(Decryptor::decrypt_to_vec)
        .unwrap_err();
    assert_eq!(plaintext, Error::InvalidHeaderMac(MacError));
}

#[test]
fn invalid_mac() {
    let data: [u8; 142] = TEST_DATA_ENC.try_into().unwrap();
    let start_mac = data.len() - 32;
    let mut data = data;
    let mut mac: [u8; 32] = data[start_mac..].try_into().unwrap();
    mac.reverse();
    data[start_mac..].copy_from_slice(&mac);
    let plaintext = Decryptor::new(&data, PASSPHRASE)
        .and_then(Decryptor::decrypt_to_vec)
        .unwrap_err();
    assert_eq!(plaintext, Error::InvalidMac(MacError));
}

#[test]
fn out_len() {
    let cipher = Decryptor::new(&TEST_DATA_ENC, PASSPHRASE).unwrap();
    assert_eq!(cipher.out_len(), 14);
}
