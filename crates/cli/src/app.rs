// SPDX-FileCopyrightText: 2023 Shun Sakai
//
// SPDX-License-Identifier: GPL-3.0-or-later

use std::path::Path;

use anyhow::{bail, Context};
use clap::Parser;
use scryptenc::{scrypt, Decryptor, Error as ScryptencError};

use crate::{
    cli::{Command, Opt},
    input, output, params, passphrase,
};

/// Ensures that there are no conflicts if reading the passphrase from stdin.
fn ensure_stdin_does_not_conflict(path: &Path) -> anyhow::Result<()> {
    if path == Path::new("-") {
        bail!("cannot read both passphrase and input data from stdin");
    }
    Ok(())
}

/// Runs the program and returns the result.
#[allow(clippy::too_many_lines)]
pub fn run() -> anyhow::Result<()> {
    let opt = Opt::parse();

    if let Some(shell) = opt.generate_completion {
        Opt::print_completion(shell);
        return Ok(());
    }

    if let Some(command) = opt.command {
        match command {
            Command::Encrypt(arg) => {
                let input = input::read(&arg.input)?;

                let passphrase = match (
                    arg.passphrase_from_tty,
                    arg.passphrase_from_stdin,
                    arg.passphrase_from_tty_once,
                    arg.passphrase_from_env,
                    arg.passphrase_from_file,
                ) {
                    (_, true, ..) => {
                        ensure_stdin_does_not_conflict(&arg.input)?;
                        passphrase::read_passphrase_from_stdin()
                    }
                    (_, _, true, ..) => passphrase::read_passphrase_from_tty_once(),
                    (.., Some(env), _) => passphrase::read_passphrase_from_env(&env),
                    (.., Some(file)) => passphrase::read_passphrase_from_file(&file),
                    _ => passphrase::read_passphrase_from_tty(),
                }?;

                let params = if let (Some(log_n), Some(r), Some(p)) = (arg.log_n, arg.r, arg.p) {
                    scrypt::Params::new(log_n, r, p, scrypt::Params::RECOMMENDED_LEN)
                        .expect("encryption parameters should be valid")
                } else {
                    params::new(arg.max_memory, arg.max_memory_fraction, arg.max_time)
                };

                if arg.verbose {
                    if arg.force {
                        params::displayln_without_resources(params.log_n(), params.r(), params.p());
                    } else {
                        params::displayln_with_resources(
                            params.log_n(),
                            params.r(),
                            params.p(),
                            arg.max_memory,
                            arg.max_memory_fraction,
                            arg.max_time,
                        );
                    }
                }

                if !arg.force {
                    params::check(
                        arg.max_memory,
                        arg.max_memory_fraction,
                        arg.max_time,
                        params.log_n(),
                        params.r(),
                        params.p(),
                    )?;
                }

                let ciphertext = scryptenc::encrypt_with_params(input, passphrase, params);

                if let Some(file) = arg.output {
                    output::write_to_file(&file, &ciphertext)?;
                } else {
                    output::write_to_stdout(&ciphertext)?;
                }
            }
            Command::Decrypt(arg) => {
                let input = input::read(&arg.input)?;

                let passphrase = match (
                    arg.passphrase_from_tty,
                    arg.passphrase_from_stdin,
                    arg.passphrase_from_env,
                    arg.passphrase_from_file,
                ) {
                    (_, true, ..) => {
                        ensure_stdin_does_not_conflict(&arg.input)?;
                        passphrase::read_passphrase_from_stdin()
                    }
                    (.., Some(env), _) => passphrase::read_passphrase_from_env(&env),
                    (.., Some(file)) => passphrase::read_passphrase_from_file(&file),
                    _ => passphrase::read_passphrase_from_tty_once(),
                }?;

                let params = params::get(&input, &arg.input)?;
                if arg.verbose {
                    if arg.force {
                        params::displayln_without_resources(params.log_n(), params.r(), params.p());
                    } else {
                        params::displayln_with_resources(
                            params.log_n(),
                            params.r(),
                            params.p(),
                            arg.max_memory,
                            arg.max_memory_fraction,
                            arg.max_time,
                        );
                    }
                }

                if !arg.force {
                    params::check(
                        arg.max_memory,
                        arg.max_memory_fraction,
                        arg.max_time,
                        params.log_n(),
                        params.r(),
                        params.p(),
                    )?;
                }

                let cipher = match Decryptor::new(&input, passphrase) {
                    c @ Err(ScryptencError::InvalidHeaderMac(_)) => {
                        c.context("passphrase is incorrect")
                    }
                    c => c.context("the header in the encrypted data is invalid"),
                }?;
                let plaintext = cipher
                    .decrypt_to_vec()
                    .context("the encrypted data is corrupted")?;

                if let Some(file) = arg.output {
                    output::write_to_file(&file, &plaintext)?;
                } else {
                    output::write_to_stdout(&plaintext)?;
                }
            }
            Command::Information(arg) => {
                let input = input::read(&arg.input)?;

                let params = params::get(&input, &arg.input)?;
                #[cfg(feature = "json")]
                if arg.json {
                    let params = params::Params::new(params);
                    let output =
                        serde_json::to_vec(&params).context("could not serialize as JSON")?;
                    if let Ok(string) = std::str::from_utf8(&output) {
                        println!("{string}");
                    } else {
                        output::write_to_stdout(&output)?;
                    }
                    return Ok(());
                }
                params::displayln_without_resources(params.log_n(), params.r(), params.p());
            }
        }
    } else {
        unreachable!();
    }
    Ok(())
}
