// SPDX-FileCopyrightText: 2022 Shun Sakai
//
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! Encrypts to the scrypt encrypted data format.

use scryptenc::scrypt::Params;
use wasm_bindgen::{prelude::wasm_bindgen, JsError};

/// Encrypts `plaintext` and into a newly allocated `Uint8Array`.
///
/// This uses the recommended scrypt parameters which are sufficient for most
/// use-cases.
#[must_use]
#[wasm_bindgen]
pub fn encrypt(plaintext: &[u8], passphrase: &[u8]) -> Vec<u8> {
    scryptenc::encrypt(plaintext, passphrase)
}

#[allow(clippy::module_name_repetitions)]
/// Encrypts `plaintext` with the specified scrypt parameters and into a newly
/// allocated `Uint8Array`.
///
/// # Errors
///
/// Returns an error if the scrypt parameters is invalid.
#[wasm_bindgen(js_name = encryptWithParams)]
pub fn encrypt_with_params(
    plaintext: &[u8],
    passphrase: &[u8],
    log_n: u8,
    r: u32,
    p: u32,
) -> Result<Vec<u8>, JsError> {
    let params = Params::new(log_n, r, p, Params::RECOMMENDED_LEN)?;
    Ok(scryptenc::encrypt_with_params(
        plaintext, passphrase, params,
    ))
}
