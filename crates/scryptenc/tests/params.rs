// SPDX-FileCopyrightText: 2022 Shun Sakai
//
// SPDX-License-Identifier: Apache-2.0 OR MIT

use scryptenc::Params;

// Generated using `scrypt` version 1.3.1.
const TEST_DATA_ENC: &[u8] = include_bytes!("data/data.txt.scrypt");

#[test]
fn success() {
    let params = Params::new(TEST_DATA_ENC);
    assert!(params.is_ok());
}

#[test]
fn log_n() {
    let params = Params::new(TEST_DATA_ENC).unwrap();
    assert_eq!(params.log_n(), 10);
}

#[test]
fn n() {
    let params = Params::new(TEST_DATA_ENC).unwrap();
    assert_eq!(params.n(), 1024);
}

#[test]
fn r() {
    let params = Params::new(TEST_DATA_ENC).unwrap();
    assert_eq!(params.r(), 8);
}

#[test]
fn p() {
    let params = Params::new(TEST_DATA_ENC).unwrap();
    assert_eq!(params.p(), 1);
}

#[cfg(feature = "serde")]
#[test]
fn serialize() {
    use serde_test::{Token, assert_ser_tokens};

    assert_ser_tokens(
        &Params::new(TEST_DATA_ENC).unwrap(),
        &[
            Token::Struct {
                name: "Params",
                len: 3,
            },
            Token::Str("logN"),
            Token::U8(10),
            Token::Str("r"),
            Token::U32(8),
            Token::Str("p"),
            Token::U32(1),
            Token::StructEnd,
        ],
    );
}

#[cfg(feature = "serde")]
#[test]
fn serialize_json() {
    let params = Params::new(TEST_DATA_ENC).unwrap();
    assert_eq!(
        serde_json::to_string(&params).unwrap(),
        r#"{"logN":10,"r":8,"p":1}"#
    );
}
