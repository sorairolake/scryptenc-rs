// SPDX-FileCopyrightText: 2022 Shun Sakai
//
// SPDX-License-Identifier: Apache-2.0 OR MIT

// Lint levels of rustc.
#![forbid(unsafe_code)]
#![deny(missing_debug_implementations, missing_docs)]
#![warn(rust_2018_idioms)]
// Lint levels of Clippy.
#![warn(clippy::cargo, clippy::nursery, clippy::pedantic)]

use scryptenc::{scrypt::Params, Decryptor, Encryptor};
use sha2::{Digest, Sha256};

const PASSPHRASE: &str = "passphrase";
const TEST_DATA: &[u8] = include_bytes!("data/data.txt");

#[test]
fn success() {
    {
        let cipher = Encryptor::with_params(
            TEST_DATA,
            PASSPHRASE,
            Params::new(10, 8, 1, Params::RECOMMENDED_LEN).unwrap(),
        );
        let mut buf = vec![u8::default(); cipher.out_len()];
        cipher.encrypt(&mut buf);
        assert_ne!(buf, TEST_DATA);
        assert_eq!(buf.len(), TEST_DATA.len() + 128);

        let plaintext = Decryptor::new(buf, PASSPHRASE)
            .and_then(Decryptor::decrypt_to_vec)
            .unwrap();
        assert_eq!(plaintext, TEST_DATA);
    }

    {
        let ciphertext = Encryptor::with_params(
            TEST_DATA,
            PASSPHRASE,
            Params::new(10, 8, 1, Params::RECOMMENDED_LEN).unwrap(),
        )
        .encrypt_to_vec();
        assert_ne!(ciphertext, TEST_DATA);
        assert_eq!(ciphertext.len(), TEST_DATA.len() + 128);

        let plaintext = Decryptor::new(ciphertext, PASSPHRASE)
            .and_then(Decryptor::decrypt_to_vec)
            .unwrap();
        assert_eq!(plaintext, TEST_DATA);
    }
}

#[test]
#[should_panic(expected = "source slice length (32) does not match destination slice length (31)")]
fn invalid_output_length() {
    let cipher = Encryptor::with_params(
        TEST_DATA,
        PASSPHRASE,
        Params::new(10, 8, 1, Params::RECOMMENDED_LEN).unwrap(),
    );
    let mut buf = vec![u8::default(); cipher.out_len() - 1];
    cipher.encrypt(&mut buf);
}

#[test]
fn magic_number() {
    let ciphertext = Encryptor::with_params(
        TEST_DATA,
        PASSPHRASE,
        Params::new(10, 8, 1, Params::RECOMMENDED_LEN).unwrap(),
    )
    .encrypt_to_vec();
    assert_eq!(&ciphertext[..6], b"scrypt");
}

#[test]
fn version() {
    let ciphertext = Encryptor::with_params(
        TEST_DATA,
        PASSPHRASE,
        Params::new(10, 8, 1, Params::RECOMMENDED_LEN).unwrap(),
    )
    .encrypt_to_vec();
    assert_eq!(ciphertext[6], 0);
}

#[test]
fn log_n() {
    let ciphertext = Encryptor::with_params(
        TEST_DATA,
        PASSPHRASE,
        Params::new(10, 8, 1, Params::RECOMMENDED_LEN).unwrap(),
    )
    .encrypt_to_vec();
    assert_eq!(ciphertext[7], 10);
}

#[test]
fn r() {
    let ciphertext = Encryptor::with_params(
        TEST_DATA,
        PASSPHRASE,
        Params::new(10, 8, 1, Params::RECOMMENDED_LEN).unwrap(),
    )
    .encrypt_to_vec();
    assert_eq!(&ciphertext[8..12], u32::to_be_bytes(8));
}

#[test]
fn p() {
    let ciphertext = Encryptor::with_params(
        TEST_DATA,
        PASSPHRASE,
        Params::new(10, 8, 1, Params::RECOMMENDED_LEN).unwrap(),
    )
    .encrypt_to_vec();
    assert_eq!(&ciphertext[12..16], u32::to_be_bytes(1));
}

#[test]
fn checksum() {
    let ciphertext = Encryptor::with_params(
        TEST_DATA,
        PASSPHRASE,
        Params::new(10, 8, 1, Params::RECOMMENDED_LEN).unwrap(),
    )
    .encrypt_to_vec();
    let checksum = Sha256::digest(&ciphertext[..48]);
    assert_eq!(&ciphertext[48..64], &checksum[..16]);
}

#[test]
fn out_len() {
    let cipher = Encryptor::with_params(
        TEST_DATA,
        PASSPHRASE,
        Params::new(10, 8, 1, Params::RECOMMENDED_LEN).unwrap(),
    );
    assert_eq!(cipher.out_len(), 142);
}
