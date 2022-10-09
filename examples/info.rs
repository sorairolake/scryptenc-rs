//
// SPDX-License-Identifier: Apache-2.0 OR MIT
//
// Copyright (C) 2022 Shun Sakai
//

//! An example of reading the scrypt parameters from a file.

// Lint levels of rustc.
#![forbid(unsafe_code)]
#![deny(missing_debug_implementations, missing_docs)]
#![warn(rust_2018_idioms)]
// Lint levels of Clippy.
#![warn(clippy::cargo, clippy::nursery, clippy::pedantic)]

fn main() {
    let input = std::env::args_os().nth(1).unwrap();
    let contents = std::fs::read(input).unwrap();
    let params = scryptenc::Params::new(contents).unwrap();
    println!(
        "Parameters used: N = {}; r = {}; p = {};",
        params.n(),
        params.r(),
        params.p()
    );
}
