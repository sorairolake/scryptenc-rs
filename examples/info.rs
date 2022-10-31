//
// SPDX-License-Identifier: Apache-2.0 OR MIT
//
// Copyright (C) 2022 Shun Sakai
//

//! An example of reading the scrypt parameters from a file.

// Lint levels of rustc.
#![forbid(unsafe_code)]
#![deny(missing_debug_implementations, missing_docs)]
#![warn(rust_2018_idioms)]
// Lint levels of Clippy.
#![warn(clippy::cargo, clippy::nursery, clippy::pedantic)]

use anyhow::Context;
use clap::Parser;

#[derive(Debug, Parser)]
#[command(version, about)]
struct Opt {
    /// File to print the scrypt parameters.
    #[arg(value_name("FILE"))]
    input: std::path::PathBuf,
}

fn main() -> anyhow::Result<()> {
    let opt = Opt::parse();

    let contents = std::fs::read(&opt.input)
        .with_context(|| format!("could not read data from {}", opt.input.display()))?;

    let params = scryptenc::Params::new(contents).with_context(|| {
        format!(
            "{} is not a valid scrypt encrypted file",
            opt.input.display()
        )
    })?;
    println!(
        "Parameters used: N = {}; r = {}; p = {};",
        params.n(),
        params.r(),
        params.p()
    );
    Ok(())
}
