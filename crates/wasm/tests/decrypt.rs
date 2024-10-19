// SPDX-FileCopyrightText: 2022 Shun Sakai
//
// SPDX-License-Identifier: Apache-2.0 OR MIT

// Lint levels of rustc.
#![forbid(unsafe_code)]
#![deny(missing_debug_implementations)]
#![warn(rust_2018_idioms)]
// Lint levels of Clippy.
#![warn(clippy::cargo, clippy::nursery, clippy::pedantic)]

use wasm_bindgen::JsValue;
use wasm_bindgen_test::wasm_bindgen_test;

const PASSPHRASE: &[u8] = b"passphrase";
const TEST_DATA: &[u8] = include_bytes!("data/data.txt");
// Generated using `scrypt` version 1.3.1.
const TEST_DATA_ENC: &[u8] = include_bytes!("data/data.txt.scrypt");

#[wasm_bindgen_test]
fn success() {
    let plaintext = scryptenc_wasm::decrypt(TEST_DATA_ENC, PASSPHRASE)
        .map_err(JsValue::from)
        .unwrap();
    assert_eq!(plaintext, TEST_DATA);
}

#[wasm_bindgen_test]
fn incorrect_passphrase() {
    let result = scryptenc_wasm::decrypt(TEST_DATA_ENC, b"password");
    assert!(result.is_err());
}

#[wasm_bindgen_test]
fn invalid_input_length() {
    {
        let data =
            vec![u8::default(); (scryptenc_wasm::header_size() + scryptenc_wasm::tag_size()) - 1];
        let result = scryptenc_wasm::decrypt(&data, PASSPHRASE);
        assert!(result.is_err());
    }

    {
        let data = vec![u8::default(); scryptenc_wasm::header_size() + scryptenc_wasm::tag_size()];
        let result = scryptenc_wasm::decrypt(&data, PASSPHRASE);
        assert!(result.is_err());
    }
}

#[wasm_bindgen_test]
fn invalid_magic_number() {
    let mut data: [u8; TEST_DATA_ENC.len()] = TEST_DATA_ENC.try_into().unwrap();
    data[0] = u32::from('b').try_into().unwrap();
    let result = scryptenc_wasm::decrypt(&data, PASSPHRASE);
    assert!(result.is_err());
}

#[wasm_bindgen_test]
fn unknown_version() {
    let mut data: [u8; TEST_DATA_ENC.len()] = TEST_DATA_ENC.try_into().unwrap();
    data[6] = 1;
    let result = scryptenc_wasm::decrypt(&data, PASSPHRASE);
    assert!(result.is_err());
}

#[wasm_bindgen_test]
fn invalid_params() {
    let mut data: [u8; TEST_DATA_ENC.len()] = TEST_DATA_ENC.try_into().unwrap();

    {
        data[7] = 65;
        let result = scryptenc_wasm::decrypt(&data, PASSPHRASE);
        assert!(result.is_err());
    }

    {
        data[8..12].copy_from_slice(&u32::to_be_bytes(0));
        let result = scryptenc_wasm::decrypt(&data, PASSPHRASE);
        assert!(result.is_err());
    }

    {
        data[12..16].copy_from_slice(&u32::to_be_bytes(0));
        let result = scryptenc_wasm::decrypt(&data, PASSPHRASE);
        assert!(result.is_err());
    }
}

#[wasm_bindgen_test]
fn invalid_checksum() {
    let mut data: [u8; TEST_DATA_ENC.len()] = TEST_DATA_ENC.try_into().unwrap();
    let mut checksum: [u8; 16] = data[48..64].try_into().unwrap();
    checksum.reverse();
    data[48..64].copy_from_slice(&checksum);
    let result = scryptenc_wasm::decrypt(&data, PASSPHRASE);
    assert!(result.is_err());
}

#[wasm_bindgen_test]
fn invalid_header_mac() {
    let mut data: [u8; TEST_DATA_ENC.len()] = TEST_DATA_ENC.try_into().unwrap();
    let mut header_mac: [u8; 32] = data[64..96].try_into().unwrap();
    header_mac.reverse();
    data[64..96].copy_from_slice(&header_mac);
    let result = scryptenc_wasm::decrypt(&data, PASSPHRASE);
    assert!(result.is_err());
}

#[wasm_bindgen_test]
fn invalid_mac() {
    let data: [u8; TEST_DATA_ENC.len()] = TEST_DATA_ENC.try_into().unwrap();
    let start_mac = data.len() - scryptenc_wasm::tag_size();
    let mut data = data;
    let mut mac = data[start_mac..].to_vec();
    mac.reverse();
    data[start_mac..].copy_from_slice(&mac);
    let result = scryptenc_wasm::decrypt(&data, PASSPHRASE);
    assert!(result.is_err());
}
