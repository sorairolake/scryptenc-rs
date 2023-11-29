// SPDX-FileCopyrightText: 2022 Shun Sakai
//
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! An example of reading the scrypt parameters from a file.

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
    /// Input file.
    #[arg(value_name("FILE"))]
    input: std::path::PathBuf,
}

#[cfg(feature = "std")]
fn main() -> anyhow::Result<()> {
    use std::fs;

    use anyhow::Context;
    use clap::Parser;
    use scryptenc::Params;

    let opt = Opt::parse();

    let ciphertext = fs::read(&opt.input)
        .with_context(|| format!("could not read data from {}", opt.input.display()))?;

    let params = Params::new(ciphertext).context("data is not a valid scrypt encrypted file")?;
    println!(
        "Parameters used: N = {}; r = {}; p = {};",
        params.n(),
        params.r(),
        params.p()
    );
    Ok(())
}

#[cfg(not(feature = "std"))]
fn main() -> anyhow::Result<()> {
    anyhow::bail!("`std` feature is required");
}
