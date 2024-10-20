// SPDX-FileCopyrightText: 2022 Shun Sakai
//
// SPDX-License-Identifier: Apache-2.0 OR MIT

#![feature(test)]
// Lint levels of rustc.
#![forbid(unsafe_code)]
#![deny(missing_debug_implementations)]
#![warn(rust_2018_idioms)]
// Lint levels of Clippy.
#![warn(clippy::cargo, clippy::nursery, clippy::pedantic)]

extern crate test;

use scryptenc::Decryptor;
use test::Bencher;

const PASSPHRASE: &str = "passphrase";
// Generated using `scrypt` version 1.3.1.
const TEST_DATA_ENC: &[u8] = include_bytes!("../tests/data/data.txt.scrypt");

#[bench]
fn decrypt(b: &mut Bencher) {
    b.iter(|| {
        Decryptor::new(&TEST_DATA_ENC, PASSPHRASE)
            .and_then(|c| c.decrypt_to_vec())
            .unwrap()
    });
}
