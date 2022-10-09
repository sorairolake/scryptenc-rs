//
// SPDX-License-Identifier: Apache-2.0 OR MIT
//
// Copyright (C) 2022 Shun Sakai
//

//! An example of encrypting a file to the scrypt encrypted data format.

// Lint levels of rustc.
#![forbid(unsafe_code)]
#![deny(missing_debug_implementations, missing_docs)]
#![warn(rust_2018_idioms)]
// Lint levels of Clippy.
#![warn(clippy::cargo, clippy::nursery, clippy::pedantic)]

fn main() {
    let args: Vec<_> = std::env::args_os().skip(1).take(2).collect();
    let (from, to) = (args.get(0).unwrap(), args.get(1).unwrap());

    let mut password = String::new();
    std::io::stdin().read_line(&mut password).unwrap();
    let password = password.trim_end();

    let plaintext = std::fs::read(from).unwrap();
    let params = scrypt::Params::recommended();
    let cipher = scryptenc::Encryptor::new(password, &params, plaintext);
    let encrypted = cipher.encrypt_to_vec().unwrap();
    std::fs::write(to, encrypted).unwrap();
}
