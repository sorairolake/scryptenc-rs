//
// SPDX-License-Identifier: Apache-2.0 OR MIT
//
// Copyright (C) 2022 Shun Sakai
//

//! An example of encrypting a file to the scrypt encrypted data format.

// Lint levels of rustc.
#![forbid(unsafe_code)]
#![deny(missing_debug_implementations, missing_docs)]
#![warn(rust_2018_idioms)]
// Lint levels of Clippy.
#![warn(clippy::cargo, clippy::nursery, clippy::pedantic)]

use anyhow::Context;
use clap::Parser;

#[derive(Debug, Parser)]
#[clap(version, about)]
struct Opt {
    /// File to encrypt.
    #[clap(value_name("INFILE"))]
    input: std::path::PathBuf,

    /// File to write the result to.
    #[clap(value_name("OUTFILE"))]
    output: std::path::PathBuf,
}

fn main() -> anyhow::Result<()> {
    let opt = Opt::parse();

    let plaintext = std::fs::read(&opt.input)
        .with_context(|| format!("could not read data from {}", opt.input.display()))?;

    let password = dialoguer::Password::with_theme(&dialoguer::theme::ColorfulTheme::default())
        .with_prompt("Password")
        .with_confirmation("Confirm password", "Password mismatch")
        .interact()
        .context("could not read password")?;
    let cipher = scryptenc::Encryptor::new(password, plaintext);
    let encrypted = cipher.encrypt_to_vec();
    std::fs::write(opt.output, encrypted)
        .with_context(|| format!("could not write the result to {}", opt.input.display()))?;
    Ok(())
}
