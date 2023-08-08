// SPDX-FileCopyrightText: 2022-2023 Shun Sakai
//
// SPDX-License-Identifier: Apache-2.0 OR MIT

#![feature(test)]
// Lint levels of rustc.
#![forbid(unsafe_code)]
#![deny(missing_debug_implementations, missing_docs)]
#![warn(rust_2018_idioms)]
// Lint levels of Clippy.
#![warn(clippy::cargo, clippy::nursery, clippy::pedantic)]

extern crate test;

use test::Bencher;

use scryptenc::Encryptor;

const PASSWORD: &str = "password";
const TEST_DATA: &[u8] = include_bytes!("../tests/data/data.txt");

#[bench]
fn encrypt(b: &mut Bencher) {
    b.iter(|| Encryptor::new(TEST_DATA, PASSWORD).encrypt_to_vec());
}
