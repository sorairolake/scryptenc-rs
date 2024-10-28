// SPDX-FileCopyrightText: 2022 Shun Sakai
//
// SPDX-License-Identifier: Apache-2.0 OR MIT

#![feature(test)]

extern crate test;

use scryptenc::{scrypt::Params, Encryptor};
use test::Bencher;

const PASSPHRASE: &str = "passphrase";
const TEST_DATA: &[u8] = include_bytes!("../tests/data/data.txt");

#[bench]
fn encrypt(b: &mut Bencher) {
    b.iter(|| {
        Encryptor::with_params(
            &TEST_DATA,
            PASSPHRASE,
            Params::new(10, 8, 1, Params::RECOMMENDED_LEN).unwrap(),
        )
        .encrypt_to_vec()
    });
}
