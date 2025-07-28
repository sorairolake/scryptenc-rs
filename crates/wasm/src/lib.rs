// SPDX-FileCopyrightText: 2022 Shun Sakai
//
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! The `scryptenc-wasm` crate is the Wasm bindings for the `scryptenc` crate.

#![doc(html_root_url = "https://docs.rs/scryptenc-wasm/0.3.0/")]
// Lint levels of rustc.
#![deny(missing_docs)]

mod decrypt;
mod encrypt;
mod params;

use wasm_bindgen::prelude::wasm_bindgen;

pub use crate::{
    decrypt::decrypt,
    encrypt::{encrypt, encrypt_with_params},
    params::Params,
};

#[allow(clippy::missing_const_for_fn)]
/// The number of bytes of the header.
#[must_use]
#[wasm_bindgen(js_name = headerSize)]
pub fn header_size() -> usize {
    scryptenc::HEADER_SIZE
}

#[allow(clippy::missing_const_for_fn)]
/// The number of bytes of the MAC (authentication tag) of the scrypt encrypted
/// data format.
#[must_use]
#[wasm_bindgen(js_name = tagSize)]
pub fn tag_size() -> usize {
    scryptenc::TAG_SIZE
}

#[cfg(test)]
mod tests {
    use wasm_bindgen_test::wasm_bindgen_test;

    #[wasm_bindgen_test]
    fn header_size() {
        assert_eq!(super::header_size(), 96);
        assert_eq!(super::header_size(), scryptenc::HEADER_SIZE);
    }

    #[wasm_bindgen_test]
    fn tag_size() {
        assert_eq!(super::tag_size(), 32);
        assert_eq!(super::tag_size(), scryptenc::TAG_SIZE);
    }
}
