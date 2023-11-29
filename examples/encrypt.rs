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
#[derive(Debug, clap::Parser)]
#[command(version, about)]
struct Opt {
    /// Set the work parameter N to 2^<VALUE>.
    #[arg(long, default_value("17"), value_name("VALUE"))]
    log_n: u8,

    /// Set the work parameter r.
    #[arg(short, default_value("8"), value_name("VALUE"))]
    r: u32,

    /// Set the work parameter p.
    #[arg(short, default_value("1"), value_name("VALUE"))]
    p: u32,

    /// Input file.
    #[arg(value_name("FILE"))]
    input: std::path::PathBuf,
}

#[cfg(feature = "std")]
fn main() -> anyhow::Result<()> {
    use std::{
        fs,
        io::{self, Write},
    };

    use anyhow::Context;
    use clap::Parser;
    use dialoguer::{theme::ColorfulTheme, Password};
    use scryptenc::scrypt::Params;

    let opt = Opt::parse();

    let plaintext = fs::read(&opt.input)
        .with_context(|| format!("could not read data from {}", opt.input.display()))?;

    let passphrase = Password::with_theme(&ColorfulTheme::default())
        .with_prompt("Enter passphrase")
        .with_confirmation("Confirm passphrase", "Passphrases mismatch, try again")
        .interact()
        .context("could not read passphrase")?;
    let params = Params::new(opt.log_n, opt.r, opt.p, Params::RECOMMENDED_LEN)?;
    let ciphertext = scryptenc::encrypt_with_params(plaintext, passphrase, params);

    io::stdout()
        .write_all(&ciphertext)
        .context("could not write data to stdout")?;
    Ok(())
}

#[cfg(not(feature = "std"))]
fn main() -> anyhow::Result<()> {
    anyhow::bail!("`std` feature is required");
}
