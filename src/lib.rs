//
// SPDX-License-Identifier: Apache-2.0 OR MIT
//
// Copyright (C) 2022 Shun Sakai
//

//! The `scryptenc` crate is an implementation of the scrypt encrypted data
//! format.
//!
//! The format is defined [here][specification-url].
//!
//! [specification-url]: https://github.com/Tarsnap/scrypt/blob/d7a543fb19dca17688e34947aee4558a94200877/FORMAT

#![doc(html_root_url = "https://docs.rs/scryptenc/0.1.0/")]
#![no_std]
// Lint levels of rustc.
#![forbid(unsafe_code)]
#![deny(missing_debug_implementations, missing_docs)]
#![warn(rust_2018_idioms)]
// Lint levels of Clippy.
#![warn(clippy::cargo, clippy::nursery, clippy::pedantic)]

pub fn add(left: usize, right: usize) -> usize {
    left + right
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn it_works() {
        let result = add(2, 2);
        assert_eq!(result, 4);
    }
}
