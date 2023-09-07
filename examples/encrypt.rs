// SPDX-FileCopyrightText: 2022 Shun Sakai
//
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! An example of encrypting a file to the scrypt encrypted data format.

// Lint levels of rustc.
#![forbid(unsafe_code)]
#![deny(missing_debug_implementations)]
#![warn(rust_2018_idioms)]
// Lint levels of Clippy.
#![warn(clippy::cargo, clippy::nursery, clippy::pedantic)]

#[cfg(feature = "std")]
use anyhow::Context;
#[cfg(feature = "std")]
use clap::Parser;

#[cfg(feature = "std")]
#[derive(Debug, Parser)]
#[command(version, about)]
struct Opt {
    /// File to encrypt.
    #[arg(value_name("INFILE"))]
    input: std::path::PathBuf,

    /// File to write the result to.
    #[arg(value_name("OUTFILE"))]
    output: std::path::PathBuf,
}

#[cfg(feature = "std")]
fn main() -> anyhow::Result<()> {
    let opt = Opt::parse();

    let plaintext = std::fs::read(&opt.input)
        .with_context(|| format!("could not read data from {}", opt.input.display()))?;

    let passphrase = dialoguer::Password::with_theme(&dialoguer::theme::ColorfulTheme::default())
        .with_prompt("Enter passphrase")
        .with_confirmation("Confirm passphrase", "Passphrases mismatch, try again")
        .interact()
        .context("could not read passphrase")?;
    let cipher = scryptenc::Encryptor::new(&plaintext, passphrase);
    let ciphertext = cipher.encrypt_to_vec();
    std::fs::write(opt.output, ciphertext)
        .with_context(|| format!("could not write the result to {}", opt.input.display()))?;
    Ok(())
}

#[cfg(not(feature = "std"))]
fn main() -> anyhow::Result<()> {
    anyhow::bail!("`std` feature is required");
}
