// SPDX-FileCopyrightText: 2022 Shun Sakai
//
// SPDX-License-Identifier: Apache-2.0 OR MIT

use scryptenc_wasm::Params;
use wasm_bindgen::JsValue;
use wasm_bindgen_test::wasm_bindgen_test;

// Generated using `scrypt` version 1.3.1.
const TEST_DATA_ENC: &[u8] = include_bytes!("data/data.txt.scrypt");

#[wasm_bindgen_test]
fn success() {
    let params = Params::new(TEST_DATA_ENC);
    assert!(params.is_ok());
}

#[wasm_bindgen_test]
fn log_n() {
    let params = Params::new(TEST_DATA_ENC).map_err(JsValue::from).unwrap();
    assert_eq!(params.log_n(), 10);
}

#[wasm_bindgen_test]
fn n() {
    let params = Params::new(TEST_DATA_ENC).map_err(JsValue::from).unwrap();
    assert_eq!(params.n(), 1024);
}

#[wasm_bindgen_test]
fn r() {
    let params = Params::new(TEST_DATA_ENC).map_err(JsValue::from).unwrap();
    assert_eq!(params.r(), 8);
}

#[wasm_bindgen_test]
fn p() {
    let params = Params::new(TEST_DATA_ENC).map_err(JsValue::from).unwrap();
    assert_eq!(params.p(), 1);
}
