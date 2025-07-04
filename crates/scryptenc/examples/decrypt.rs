// SPDX-FileCopyrightText: 2022 Shun Sakai
//
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! An example of decrypting a file from the scrypt encrypted data format.

use std::{
    fs,
    io::{self, Read, Write},
    path::PathBuf,
};

use anyhow::Context;
use clap::Parser;
use dialoguer::{Password, theme::ColorfulTheme};
use scryptenc::{Decryptor, Error};

#[derive(Debug, Parser)]
#[command(version, about)]
struct Opt {
    /// Output the result to a file.
    #[arg(short, long, value_name("FILE"))]
    output: Option<PathBuf>,

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

    let passphrase = Password::with_theme(&ColorfulTheme::default())
        .with_prompt("Enter passphrase")
        .interact()
        .context("could not read passphrase")?;
    let cipher = match Decryptor::new(&ciphertext, passphrase) {
        c @ Err(Error::InvalidHeaderMac(_)) => c.context("passphrase is incorrect"),
        c => c.context("the header in the encrypted data is invalid"),
    }?;
    let plaintext = cipher
        .decrypt_to_vec()
        .context("the encrypted data is corrupted")?;

    if let Some(file) = opt.output {
        fs::write(&file, plaintext)
            .with_context(|| format!("could not write data to {}", file.display()))
    } else {
        io::stdout()
            .write_all(&plaintext)
            .context("could not write data to standard output")
    }
}
