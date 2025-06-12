// SPDX-FileCopyrightText: 2023 Shun Sakai
//
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! The scrypt parameters.

use wasm_bindgen::{JsError, prelude::wasm_bindgen};

/// The scrypt parameters used for the encrypted data.
#[derive(Clone, Copy, Debug)]
#[wasm_bindgen]
pub struct Params(scryptenc::Params);

#[wasm_bindgen]
impl Params {
    /// Creates a new instance of the scrypt parameters from `ciphertext`.
    ///
    /// # Errors
    ///
    /// Returns an error if any of the following are true:
    ///
    /// - `ciphertext` is shorter than 128 bytes.
    /// - The magic number is invalid.
    /// - The version number is the unrecognized scrypt version number.
    /// - The scrypt parameters are invalid.
    #[inline]
    #[wasm_bindgen(constructor)]
    pub fn new(ciphertext: &[u8]) -> Result<Self, JsError> {
        scryptenc::Params::new(ciphertext)
            .map(Self)
            .map_err(JsError::from)
    }

    #[allow(clippy::missing_const_for_fn)]
    /// Gets log<sub>2</sub> of the scrypt parameter `N`.
    #[must_use]
    #[inline]
    #[wasm_bindgen(js_name = logN, getter)]
    pub fn log_n(&self) -> u8 {
        self.0.log_n()
    }

    #[allow(clippy::missing_const_for_fn)]
    /// Gets `N` parameter.
    #[must_use]
    #[inline]
    #[wasm_bindgen(getter)]
    pub fn n(&self) -> u64 {
        self.0.n()
    }

    #[allow(clippy::missing_const_for_fn)]
    /// Gets `r` parameter.
    #[must_use]
    #[inline]
    #[wasm_bindgen(getter)]
    pub fn r(&self) -> u32 {
        self.0.r()
    }

    #[allow(clippy::missing_const_for_fn)]
    /// Gets `p` parameter.
    #[must_use]
    #[inline]
    #[wasm_bindgen(getter)]
    pub fn p(&self) -> u32 {
        self.0.p()
    }
}
