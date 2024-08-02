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

use std::{
    fs,
    io::{self, Read},
    path::PathBuf,
};

use anyhow::Context;
use clap::Parser;
use scryptenc::Params;

#[derive(Debug, Parser)]
#[command(version, about)]
struct Opt {
    /// Output the encryption parameters as JSON.
    #[arg(short, long)]
    json: bool,

    /// Input file.
    ///
    /// If [FILE] is not specified, data will be read from standard input.
    #[arg(value_name("FILE"))]
    input: Option<PathBuf>,
}

fn main() -> anyhow::Result<()> {
    let opt = Opt::parse();

    let ciphertext = if let Some(file) = opt.input {
        fs::read(&file).with_context(|| format!("could not read data from {}", file.display()))
    } else {
        let mut buf = Vec::new();
        io::stdin()
            .read_to_end(&mut buf)
            .context("could not read data from standard input")?;
        Ok(buf)
    }?;

    let params = Params::new(ciphertext).context("data is not a valid scrypt encrypted file")?;
    if opt.json {
        let output = serde_json::to_string(&params).context("could not serialize as JSON")?;
        println!("{output}");
    } else {
        println!(
            "Parameters used: logN = {}; r = {}; p = {};",
            params.log_n(),
            params.r(),
            params.p()
        );
    }
    Ok(())
}
