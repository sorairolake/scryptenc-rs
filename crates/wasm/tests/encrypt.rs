// SPDX-FileCopyrightText: 2022 Shun Sakai
//
// SPDX-License-Identifier: Apache-2.0 OR MIT

// Lint levels of rustc.
#![forbid(unsafe_code)]
#![deny(missing_debug_implementations, missing_docs)]
#![warn(rust_2018_idioms)]
// Lint levels of Clippy.
#![warn(clippy::cargo, clippy::nursery, clippy::pedantic)]

use wasm_bindgen::JsValue;
use wasm_bindgen_test::wasm_bindgen_test;

const PASSPHRASE: &[u8] = b"passphrase";
const TEST_DATA: &[u8] = include_bytes!("data/data.txt");

#[wasm_bindgen_test]
fn success() {
    let ciphertext = scryptenc_wasm::encrypt_with_params(TEST_DATA, PASSPHRASE, 10, 8, 1)
        .map_err(JsValue::from)
        .unwrap();
    assert_ne!(ciphertext, TEST_DATA);
    assert_eq!(
        ciphertext.len(),
        TEST_DATA.len() + scryptenc_wasm::header_size() + scryptenc_wasm::tag_size()
    );

    let plaintext = scryptenc_wasm::decrypt(&ciphertext, PASSPHRASE)
        .map_err(JsValue::from)
        .unwrap();
    assert_eq!(plaintext, TEST_DATA);
}

#[wasm_bindgen_test]
fn magic_number() {
    let ciphertext = scryptenc_wasm::encrypt_with_params(TEST_DATA, PASSPHRASE, 10, 8, 1)
        .map_err(JsValue::from)
        .unwrap();
    assert_eq!(&ciphertext[..6], b"scrypt");
}

#[wasm_bindgen_test]
fn version() {
    let ciphertext = scryptenc_wasm::encrypt_with_params(TEST_DATA, PASSPHRASE, 10, 8, 1)
        .map_err(JsValue::from)
        .unwrap();
    assert_eq!(ciphertext[6], 0);
}

#[wasm_bindgen_test]
fn log_n() {
    let ciphertext = scryptenc_wasm::encrypt_with_params(TEST_DATA, PASSPHRASE, 10, 8, 1)
        .map_err(JsValue::from)
        .unwrap();
    assert_eq!(ciphertext[7], 10);
}

#[wasm_bindgen_test]
fn r() {
    let ciphertext = scryptenc_wasm::encrypt_with_params(TEST_DATA, PASSPHRASE, 10, 8, 1)
        .map_err(JsValue::from)
        .unwrap();
    assert_eq!(&ciphertext[8..12], u32::to_be_bytes(8));
}

#[wasm_bindgen_test]
fn p() {
    let ciphertext = scryptenc_wasm::encrypt_with_params(TEST_DATA, PASSPHRASE, 10, 8, 1)
        .map_err(JsValue::from)
        .unwrap();
    assert_eq!(&ciphertext[12..16], u32::to_be_bytes(1));
}