// SPDX-FileCopyrightText: 2022 Shun Sakai
//
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! Decrypts from the scrypt encrypted data format.

use wasm_bindgen::{prelude::wasm_bindgen, JsError};

/// Decrypts `ciphertext` and into a newly allocated `Uint8Array`.
///
/// # Errors
///
/// Returns an error if any of the following are true:
///
/// - `ciphertext` is shorter than 128 bytes.
/// - The magic number is invalid.
/// - The version number is the unrecognized scrypt version number.
/// - The scrypt parameters are invalid.
/// - The checksum of the header mismatch.
/// - The MAC (authentication tag) of the header is invalid.
/// - The MAC (authentication tag) of the scrypt encrypted data format is
///   invalid.
#[inline]
#[wasm_bindgen]
pub fn decrypt(ciphertext: &[u8], passphrase: &[u8]) -> Result<Vec<u8>, JsError> {
    scryptenc::decrypt(ciphertext, passphrase).map_err(JsError::from)
}
