//
// SPDX-License-Identifier: Apache-2.0 OR MIT
//
// Copyright (C) 2022 Shun Sakai
//

#![feature(test)]
// Lint levels of rustc.
#![forbid(unsafe_code)]
#![deny(missing_debug_implementations, missing_docs)]
#![warn(rust_2018_idioms)]
// Lint levels of Clippy.
#![warn(clippy::cargo, clippy::nursery, clippy::pedantic)]

extern crate test;

use test::Bencher;

use scrypt::Params;
use scryptenc::Encryptor;

const PASSWORD: &str = "password";
const DATA: &str = "Hello, world!";

#[bench]
fn encrypt(b: &mut Bencher) {
    b.iter(|| {
        Encryptor::with_params(DATA, PASSWORD, Params::new(10, 8, 1).unwrap()).encrypt_to_vec()
    });
}
