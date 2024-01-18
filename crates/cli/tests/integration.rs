// SPDX-FileCopyrightText: 2022 Shun Sakai
//
// SPDX-License-Identifier: GPL-3.0-or-later

// Lint levels of rustc.
#![forbid(unsafe_code)]
#![deny(missing_debug_implementations)]
#![warn(rust_2018_idioms)]
// Lint levels of Clippy.
#![warn(clippy::cargo, clippy::nursery, clippy::pedantic)]
#![allow(clippy::multiple_crate_versions)]

use assert_cmd::Command;
use predicates::prelude::predicate;

fn command() -> Command {
    let mut command = Command::cargo_bin("rscrypt").unwrap();
    command.current_dir("tests");
    command
}

#[test]
fn generate_completion_conflicts_with_subcommands() {
    command()
        .arg("--generate-completion")
        .arg("bash")
        .arg("enc")
        .assert()
        .failure()
        .code(2)
        .stderr(predicate::str::contains(
            "the subcommand 'enc' cannot be used with '--generate-completion <SHELL>'",
        ));
    command()
        .arg("--generate-completion")
        .arg("bash")
        .arg("dec")
        .assert()
        .failure()
        .code(2)
        .stderr(predicate::str::contains(
            "the subcommand 'dec' cannot be used with '--generate-completion <SHELL>'",
        ));
    command()
        .arg("--generate-completion")
        .arg("bash")
        .arg("info")
        .assert()
        .failure()
        .code(2)
        .stderr(predicate::str::contains(
            "the subcommand 'info' cannot be used with '--generate-completion <SHELL>'",
        ));
}

#[test]
fn generate_completion() {
    command()
        .arg("--generate-completion")
        .arg("bash")
        .assert()
        .success()
        .stdout(predicate::ne(""));
    command()
        .arg("--generate-completion")
        .arg("elvish")
        .assert()
        .success()
        .stdout(predicate::ne(""));
    command()
        .arg("--generate-completion")
        .arg("fish")
        .assert()
        .success()
        .stdout(predicate::ne(""));
    command()
        .arg("--generate-completion")
        .arg("nushell")
        .assert()
        .success()
        .stdout(predicate::ne(""));
    command()
        .arg("--generate-completion")
        .arg("powershell")
        .assert()
        .success()
        .stdout(predicate::ne(""));
    command()
        .arg("--generate-completion")
        .arg("zsh")
        .assert()
        .success()
        .stdout(predicate::ne(""));
}

#[test]
fn generate_completion_with_invalid_shell() {
    command()
        .arg("--generate-completion")
        .arg("a")
        .assert()
        .failure()
        .code(2)
        .stderr(predicate::str::contains(
            "invalid value 'a' for '--generate-completion <SHELL>'",
        ));
}

#[test]
fn long_version() {
    command()
        .arg("--version")
        .assert()
        .success()
        .stdout(predicate::str::contains(include_str!(
            "assets/long-version.md"
        )));
}

#[test]
fn after_long_help() {
    command()
        .arg("--help")
        .assert()
        .success()
        .stdout(predicate::str::contains(include_str!(
            "assets/after-long-help.md"
        )));
}

#[test]
fn basic_encrypt() {
    command()
        .arg("enc")
        .arg("--log-n")
        .arg("10")
        .arg("-r")
        .arg("8")
        .arg("-p")
        .arg("1")
        .arg("--passphrase-from-stdin")
        .arg("data/data.txt")
        .write_stdin("passphrase")
        .assert()
        .success();
}

#[test]
fn encrypt_if_non_existent_input_file() {
    let command = command()
        .arg("enc")
        .arg("--passphrase-from-stdin")
        .arg("non_existent.txt")
        .write_stdin("passphrase")
        .assert()
        .failure()
        .code(66)
        .stderr(predicate::str::contains(
            "could not read data from non_existent.txt",
        ));
    if cfg!(windows) {
        command.stderr(predicate::str::contains(
            "The system cannot find the file specified. (os error 2)",
        ));
    } else {
        command.stderr(predicate::str::contains(
            "No such file or directory (os error 2)",
        ));
    }
}

#[test]
fn encrypt_if_output_is_directory() {
    let command = command()
        .arg("enc")
        .arg("--passphrase-from-stdin")
        .arg("data/data.txt")
        .arg("data/dummy")
        .write_stdin("passphrase")
        .assert()
        .failure()
        .stderr(predicate::str::contains(
            "could not write data to data/dummy",
        ));
    if cfg!(windows) {
        command.stderr(predicate::str::contains("Access is denied. (os error 5)"));
    } else {
        command.stderr(predicate::str::contains("Is a directory (os error 21)"));
    }
}

#[test]
fn encrypt_with_max_memory() {
    command()
        .arg("enc")
        .arg("-M")
        .arg("64MiB")
        .arg("-t")
        .arg("10s")
        .arg("--passphrase-from-stdin")
        .arg("-v")
        .arg("data/data.txt")
        .write_stdin("passphrase")
        .assert()
        .success()
        .stderr(predicate::str::contains("64 MiB available"));
    command()
        .arg("enc")
        .arg("-M")
        .arg("64.0MiB")
        .arg("-t")
        .arg("10s")
        .arg("--passphrase-from-stdin")
        .arg("-v")
        .arg("data/data.txt")
        .write_stdin("passphrase")
        .assert()
        .success()
        .stderr(predicate::str::contains("64 MiB available"));
    command()
        .arg("enc")
        .arg("-M")
        .arg("64.5MiB")
        .arg("-t")
        .arg("10s")
        .arg("--passphrase-from-stdin")
        .arg("-v")
        .arg("data/data.txt")
        .write_stdin("passphrase")
        .assert()
        .success()
        .stderr(predicate::str::contains("64.5 MiB available"));
    command()
        .arg("enc")
        .arg("-M")
        .arg("64.56MiB")
        .arg("-t")
        .arg("10s")
        .arg("--passphrase-from-stdin")
        .arg("-v")
        .arg("data/data.txt")
        .write_stdin("passphrase")
        .assert()
        .success()
        .stderr(predicate::str::contains("64.6 MiB available"));
}

#[test]
fn invalid_amount_of_ram_for_encrypt_command() {
    command()
        .arg("enc")
        .arg("-M")
        .arg("1023.99KiB")
        .arg("--passphrase-from-stdin")
        .arg("data/data.txt")
        .write_stdin("passphrase")
        .assert()
        .failure()
        .code(2)
        .stderr(predicate::str::contains("amount of RAM is less than 1 MiB"));
    command()
        .arg("enc")
        .arg("-M")
        .arg("16.01EiB")
        .arg("--passphrase-from-stdin")
        .arg("data/data.txt")
        .write_stdin("passphrase")
        .assert()
        .failure()
        .code(2)
        .stderr(predicate::str::contains(
            "amount of RAM is not a valid value: the value 16.01 exceeds the valid range",
        ));
    command()
        .arg("enc")
        .arg("-M")
        .arg("BYTE")
        .arg("--passphrase-from-stdin")
        .arg("data/data.txt")
        .write_stdin("passphrase")
        .assert()
        .failure()
        .code(2)
        .stderr(predicate::str::contains(
            "amount of RAM is not a valid value: the character 'B' is not a number",
        ));
}

#[test]
fn invalid_fraction_of_the_available_ram_for_encrypt_command() {
    command()
        .arg("enc")
        .arg("-m")
        .arg("0")
        .arg("--passphrase-from-stdin")
        .arg("data/data.txt")
        .write_stdin("passphrase")
        .assert()
        .failure()
        .code(2)
        .stderr(predicate::str::contains("fraction is 0"));
    command()
        .arg("enc")
        .arg("-m")
        .arg("0.51")
        .arg("--passphrase-from-stdin")
        .arg("data/data.txt")
        .write_stdin("passphrase")
        .assert()
        .failure()
        .code(2)
        .stderr(predicate::str::contains("fraction is more than 0.5"));
    command()
        .arg("enc")
        .arg("-m")
        .arg("RATE")
        .arg("--passphrase-from-stdin")
        .arg("data/data.txt")
        .write_stdin("passphrase")
        .assert()
        .failure()
        .code(2)
        .stderr(predicate::str::contains("fraction is not a valid number"));
}

#[test]
fn encrypt_with_max_time() {
    command()
        .arg("enc")
        .arg("-t")
        .arg("10s")
        .arg("--passphrase-from-stdin")
        .arg("-v")
        .arg("data/data.txt")
        .write_stdin("passphrase")
        .assert()
        .success()
        .stderr(predicate::str::contains("limit: 10.0s"));
}

#[test]
fn invalid_time_for_encrypt_command() {
    command()
        .arg("enc")
        .arg("-t")
        .arg("NaN")
        .arg("--passphrase-from-stdin")
        .arg("data/data.txt")
        .write_stdin("passphrase")
        .assert()
        .failure()
        .code(2)
        .stderr(predicate::str::contains(
            "time is not a valid value: expected number at 0",
        ));
    command()
        .arg("enc")
        .arg("-t")
        .arg("1")
        .arg("--passphrase-from-stdin")
        .arg("data/data.txt")
        .write_stdin("passphrase")
        .assert()
        .failure()
        .code(2)
        .stderr(predicate::str::contains(
            "time is not a valid value: time unit needed",
        ));
    command()
        .arg("enc")
        .arg("-t")
        .arg("1a")
        .arg("--passphrase-from-stdin")
        .arg("data/data.txt")
        .write_stdin("passphrase")
        .assert()
        .failure()
        .code(2)
        .stderr(predicate::str::contains(
            r#"time is not a valid value: unknown time unit "a""#,
        ));
    command()
        .arg("enc")
        .arg("-t")
        .arg("10000000000000y")
        .arg("--passphrase-from-stdin")
        .arg("data/data.txt")
        .write_stdin("passphrase")
        .assert()
        .failure()
        .code(2)
        .stderr(predicate::str::contains(
            "time is not a valid value: number is too large",
        ));
}

#[test]
fn validate_parameters_group_for_encrypt_command() {
    command()
        .arg("enc")
        .arg("--log-n")
        .arg("10")
        .arg("--passphrase-from-stdin")
        .arg("data/data.txt")
        .write_stdin("passphrase")
        .assert()
        .failure()
        .code(2)
        .stderr(predicate::str::contains(
            "the following required arguments were not provided",
        ))
        .stderr(predicate::str::contains("-r <VALUE>"))
        .stderr(predicate::str::contains("-p <VALUE>"));
    command()
        .arg("enc")
        .arg("-r")
        .arg("8")
        .arg("--passphrase-from-stdin")
        .arg("data/data.txt")
        .write_stdin("passphrase")
        .assert()
        .failure()
        .code(2)
        .stderr(predicate::str::contains(
            "the following required arguments were not provided",
        ))
        .stderr(predicate::str::contains("--log-n <VALUE>"))
        .stderr(predicate::str::contains("-p <VALUE>"));
    command()
        .arg("enc")
        .arg("-p")
        .arg("1")
        .arg("--passphrase-from-stdin")
        .arg("data/data.txt")
        .write_stdin("passphrase")
        .assert()
        .failure()
        .code(2)
        .stderr(predicate::str::contains(
            "the following required arguments were not provided",
        ))
        .stderr(predicate::str::contains("--log-n <VALUE>"))
        .stderr(predicate::str::contains("-r <VALUE>"));
}

#[test]
fn validate_work_parameter_ranges_for_encrypt_command() {
    command()
        .arg("enc")
        .arg("--log-n")
        .arg("9")
        .arg("-r")
        .arg("8")
        .arg("-p")
        .arg("1")
        .arg("--passphrase-from-stdin")
        .arg("data/data.txt")
        .write_stdin("passphrase")
        .assert()
        .failure()
        .stderr(predicate::str::contains(
            "invalid value '9' for '--log-n <VALUE>': 9 is not in 10..=40",
        ));
    command()
        .arg("enc")
        .arg("--log-n")
        .arg("41")
        .arg("-r")
        .arg("8")
        .arg("-p")
        .arg("1")
        .arg("--passphrase-from-stdin")
        .arg("data/data.txt")
        .write_stdin("passphrase")
        .assert()
        .failure()
        .stderr(predicate::str::contains(
            "invalid value '41' for '--log-n <VALUE>': 41 is not in 10..=40",
        ));
    command()
        .arg("enc")
        .arg("--log-n")
        .arg("10")
        .arg("-r")
        .arg("0")
        .arg("-p")
        .arg("1")
        .arg("--passphrase-from-stdin")
        .arg("data/data.txt")
        .write_stdin("passphrase")
        .assert()
        .failure()
        .stderr(predicate::str::contains(
            "invalid value '0' for '-r <VALUE>': 0 is not in 1..=32",
        ));
    command()
        .arg("enc")
        .arg("--log-n")
        .arg("10")
        .arg("-r")
        .arg("33")
        .arg("-p")
        .arg("1")
        .arg("--passphrase-from-stdin")
        .arg("data/data.txt")
        .write_stdin("passphrase")
        .assert()
        .failure()
        .stderr(predicate::str::contains(
            "invalid value '33' for '-r <VALUE>': 33 is not in 1..=32",
        ));
    command()
        .arg("enc")
        .arg("--log-n")
        .arg("10")
        .arg("-r")
        .arg("8")
        .arg("-p")
        .arg("0")
        .arg("--passphrase-from-stdin")
        .arg("data/data.txt")
        .write_stdin("passphrase")
        .assert()
        .failure()
        .stderr(predicate::str::contains(
            "invalid value '0' for '-p <VALUE>': 0 is not in 1..=32",
        ));
    command()
        .arg("enc")
        .arg("--log-n")
        .arg("10")
        .arg("-r")
        .arg("8")
        .arg("-p")
        .arg("33")
        .arg("--passphrase-from-stdin")
        .arg("data/data.txt")
        .write_stdin("passphrase")
        .assert()
        .failure()
        .stderr(predicate::str::contains(
            "invalid value '33' for '-p <VALUE>': 33 is not in 1..=32",
        ));
}

#[test]
fn validate_conflicts_if_reading_from_stdin_for_encrypt_command() {
    command()
        .arg("enc")
        .arg("--log-n")
        .arg("10")
        .arg("-r")
        .arg("8")
        .arg("-p")
        .arg("1")
        .arg("--passphrase-from-stdin")
        .arg("-")
        .write_stdin("passphrase")
        .assert()
        .failure()
        .stderr(predicate::str::ends_with(
            "cannot read both passphrase and input data from stdin\n",
        ));
}

#[test]
fn encrypt_verbose() {
    command()
        .arg("enc")
        .arg("--log-n")
        .arg("10")
        .arg("-r")
        .arg("8")
        .arg("-p")
        .arg("1")
        .arg("--passphrase-from-stdin")
        .arg("-v")
        .arg("data/data.txt")
        .write_stdin("passphrase")
        .assert()
        .success()
        .stderr(predicate::str::starts_with(
            "Parameters used: N = 1024; r = 8; p = 1;",
        ));
}

#[test]
fn long_version_for_encrypt_command() {
    command()
        .arg("enc")
        .arg("--version")
        .assert()
        .success()
        .stdout(predicate::str::contains(include_str!(
            "assets/long-version.md"
        )));
}

#[test]
fn after_long_help_for_encrypt_command() {
    command()
        .arg("enc")
        .arg("--help")
        .assert()
        .success()
        .stdout(predicate::str::contains(include_str!(
            "assets/enc-after-long-help.md"
        )));
}

#[test]
fn basic_decrypt() {
    command()
        .arg("dec")
        .arg("--passphrase-from-stdin")
        .arg("data/data.txt.scrypt")
        .write_stdin("passphrase")
        .assert()
        .success()
        .stdout(predicate::eq("Hello, world!\n"));
}

#[test]
fn decrypt_if_non_existent_input_file() {
    let command = command()
        .arg("dec")
        .arg("--passphrase-from-stdin")
        .arg("non_existent.txt.scrypt")
        .write_stdin("passphrase")
        .assert()
        .failure()
        .code(66)
        .stderr(predicate::str::contains(
            "could not read data from non_existent.txt.scrypt",
        ));
    if cfg!(windows) {
        command.stderr(predicate::str::contains(
            "The system cannot find the file specified. (os error 2)",
        ));
    } else {
        command.stderr(predicate::str::contains(
            "No such file or directory (os error 2)",
        ));
    }
}

#[test]
fn decrypt_if_output_is_directory() {
    let command = command()
        .arg("dec")
        .arg("--passphrase-from-stdin")
        .arg("data/data.txt.scrypt")
        .arg("data/dummy")
        .write_stdin("passphrase")
        .assert()
        .failure()
        .stderr(predicate::str::contains(
            "could not write data to data/dummy",
        ));
    if cfg!(windows) {
        command.stderr(predicate::str::contains("Access is denied. (os error 5)"));
    } else {
        command.stderr(predicate::str::contains("Is a directory (os error 21)"));
    }
}

#[test]
fn decrypt_with_max_memory() {
    command()
        .arg("dec")
        .arg("-M")
        .arg("64MiB")
        .arg("--passphrase-from-stdin")
        .arg("-v")
        .arg("data/data.txt.scrypt")
        .write_stdin("passphrase")
        .assert()
        .success()
        .stderr(predicate::str::contains("64 MiB available"));
    command()
        .arg("dec")
        .arg("-M")
        .arg("64.0MiB")
        .arg("--passphrase-from-stdin")
        .arg("-v")
        .arg("data/data.txt.scrypt")
        .write_stdin("passphrase")
        .assert()
        .success()
        .stderr(predicate::str::contains("64 MiB available"));
    command()
        .arg("dec")
        .arg("-M")
        .arg("64.5MiB")
        .arg("--passphrase-from-stdin")
        .arg("-v")
        .arg("data/data.txt.scrypt")
        .write_stdin("passphrase")
        .assert()
        .success()
        .stderr(predicate::str::contains("64.5 MiB available"));
    command()
        .arg("dec")
        .arg("-M")
        .arg("64.56MiB")
        .arg("--passphrase-from-stdin")
        .arg("-v")
        .arg("data/data.txt.scrypt")
        .write_stdin("passphrase")
        .assert()
        .success()
        .stderr(predicate::str::contains("64.6 MiB available"));
}

#[test]
fn invalid_amount_of_ram_for_decrypt_command() {
    command()
        .arg("dec")
        .arg("-M")
        .arg("1023.99KiB")
        .arg("--passphrase-from-stdin")
        .arg("data/data.txt.scrypt")
        .write_stdin("passphrase")
        .assert()
        .failure()
        .code(2)
        .stderr(predicate::str::contains("amount of RAM is less than 1 MiB"));
    command()
        .arg("dec")
        .arg("-M")
        .arg("16.01EiB")
        .arg("--passphrase-from-stdin")
        .arg("data/data.txt.scrypt")
        .write_stdin("passphrase")
        .assert()
        .failure()
        .code(2)
        .stderr(predicate::str::contains(
            "amount of RAM is not a valid value: the value 16.01 exceeds the valid range",
        ));
    command()
        .arg("dec")
        .arg("-M")
        .arg("BYTE")
        .arg("--passphrase-from-stdin")
        .arg("data/data.txt.scrypt")
        .write_stdin("passphrase")
        .assert()
        .failure()
        .code(2)
        .stderr(predicate::str::contains(
            "amount of RAM is not a valid value: the character 'B' is not a number",
        ));
}

#[test]
fn invalid_fraction_of_the_available_ram_for_decrypt_command() {
    command()
        .arg("dec")
        .arg("-m")
        .arg("0")
        .arg("--passphrase-from-stdin")
        .arg("data/data.txt.scrypt")
        .write_stdin("passphrase")
        .assert()
        .failure()
        .code(2)
        .stderr(predicate::str::contains("fraction is 0"));
    command()
        .arg("dec")
        .arg("-m")
        .arg("0.51")
        .arg("--passphrase-from-stdin")
        .arg("data/data.txt.scrypt")
        .write_stdin("passphrase")
        .assert()
        .failure()
        .code(2)
        .stderr(predicate::str::contains("fraction is more than 0.5"));
    command()
        .arg("dec")
        .arg("-m")
        .arg("RATE")
        .arg("--passphrase-from-stdin")
        .arg("data/data.txt.scrypt")
        .write_stdin("passphrase")
        .assert()
        .failure()
        .code(2)
        .stderr(predicate::str::contains("fraction is not a valid number"));
}

#[test]
fn decrypt_with_max_time() {
    command()
        .arg("dec")
        .arg("-t")
        .arg("3600s")
        .arg("--passphrase-from-stdin")
        .arg("-v")
        .arg("data/data.txt.scrypt")
        .write_stdin("passphrase")
        .assert()
        .success()
        .stderr(predicate::str::contains("limit: 3600.0s"));
}

#[test]
fn invalid_time_for_decrypt_command() {
    command()
        .arg("dec")
        .arg("-t")
        .arg("NaN")
        .arg("--passphrase-from-stdin")
        .arg("data/data.txt.scrypt")
        .write_stdin("passphrase")
        .assert()
        .failure()
        .code(2)
        .stderr(predicate::str::contains(
            "time is not a valid value: expected number at 0",
        ));
    command()
        .arg("dec")
        .arg("-t")
        .arg("1")
        .arg("--passphrase-from-stdin")
        .arg("data/data.txt.scrypt")
        .write_stdin("passphrase")
        .assert()
        .failure()
        .code(2)
        .stderr(predicate::str::contains(
            "time is not a valid value: time unit needed",
        ));
    command()
        .arg("dec")
        .arg("-t")
        .arg("1a")
        .arg("--passphrase-from-stdin")
        .arg("data/data.txt.scrypt")
        .write_stdin("passphrase")
        .assert()
        .failure()
        .code(2)
        .stderr(predicate::str::contains(
            r#"time is not a valid value: unknown time unit "a""#,
        ));
    command()
        .arg("dec")
        .arg("-t")
        .arg("10000000000000y")
        .arg("--passphrase-from-stdin")
        .arg("data/data.txt.scrypt")
        .write_stdin("passphrase")
        .assert()
        .failure()
        .code(2)
        .stderr(predicate::str::contains(
            "time is not a valid value: number is too large",
        ));
}

#[test]
fn validate_conflicts_if_reading_from_stdin_for_decrypt_command() {
    command()
        .arg("dec")
        .arg("--passphrase-from-stdin")
        .arg("-")
        .write_stdin("passphrase")
        .assert()
        .failure()
        .stderr(predicate::str::ends_with(
            "cannot read both passphrase and input data from stdin\n",
        ));
}

#[test]
fn decrypt_if_input_file_is_invalid() {
    command()
        .arg("dec")
        .arg("--passphrase-from-stdin")
        .arg("data/data.txt")
        .write_stdin("passphrase")
        .assert()
        .failure()
        .code(7)
        .stderr(predicate::str::contains(
            "data is not a valid scrypt encrypted file",
        ))
        .stderr(predicate::str::contains(
            "encrypted data is shorter than 128 bytes",
        ));
}

#[test]
fn decrypt_if_passphrase_is_incorrect() {
    command()
        .arg("dec")
        .arg("--passphrase-from-stdin")
        .arg("data/data.txt.scrypt")
        .write_stdin("password")
        .assert()
        .failure()
        .code(11)
        .stderr(predicate::str::contains("passphrase is incorrect"))
        .stderr(predicate::str::contains("invalid header MAC"))
        .stderr(predicate::str::contains("MAC tag mismatch"));
}

#[test]
fn decrypt_verbose() {
    command()
        .arg("dec")
        .arg("--passphrase-from-stdin")
        .arg("-v")
        .arg("data/data.txt.scrypt")
        .write_stdin("passphrase")
        .assert()
        .success()
        .stdout(predicate::eq("Hello, world!\n"))
        .stderr(predicate::str::starts_with(
            "Parameters used: N = 1024; r = 8; p = 1;",
        ));
}

#[test]
fn long_version_for_decrypt_command() {
    command()
        .arg("dec")
        .arg("--version")
        .assert()
        .success()
        .stdout(predicate::str::contains(include_str!(
            "assets/long-version.md"
        )));
}

#[test]
fn after_long_help_for_decrypt_command() {
    command()
        .arg("dec")
        .arg("--help")
        .assert()
        .success()
        .stdout(predicate::str::contains(include_str!(
            "assets/dec-after-long-help.md"
        )));
}

#[test]
fn basic_information() {
    command()
        .arg("info")
        .arg("data/data.txt.scrypt")
        .assert()
        .success()
        .stderr(predicate::str::starts_with(
            "Parameters used: N = 1024; r = 8; p = 1;",
        ));
}

#[test]
fn information_if_non_existent_input_file() {
    let command = command()
        .arg("info")
        .arg("non_existent.txt.scrypt")
        .assert()
        .failure()
        .code(66)
        .stderr(predicate::str::contains(
            "could not read data from non_existent.txt.scrypt",
        ));
    if cfg!(windows) {
        command.stderr(predicate::str::contains(
            "The system cannot find the file specified. (os error 2)",
        ));
    } else {
        command.stderr(predicate::str::contains(
            "No such file or directory (os error 2)",
        ));
    }
}

#[cfg(not(feature = "json"))]
#[test]
fn information_command_without_default_feature() {
    command()
        .arg("info")
        .arg("-j")
        .arg("data/data.txt.scrypt")
        .assert()
        .failure()
        .code(2)
        .stderr(predicate::str::contains("unexpected argument '-j' found"));
}

#[cfg(feature = "json")]
#[test]
fn information_as_json() {
    command()
        .arg("info")
        .arg("-j")
        .arg("data/data.txt.scrypt")
        .assert()
        .success()
        .stdout(predicate::eq(concat!(r#"{"N":1024,"r":8,"p":1}"#, '\n')));
}

#[test]
fn information_if_input_file_is_invalid() {
    command()
        .arg("info")
        .arg("data/data.txt")
        .assert()
        .failure()
        .code(7)
        .stderr(predicate::str::contains(
            "data is not a valid scrypt encrypted file",
        ))
        .stderr(predicate::str::contains(
            "encrypted data is shorter than 128 bytes",
        ));
}

#[test]
fn long_version_for_information_command() {
    command()
        .arg("info")
        .arg("--version")
        .assert()
        .success()
        .stdout(predicate::str::contains(include_str!(
            "assets/long-version.md"
        )));
}

#[test]
fn after_long_help_for_information_command() {
    command()
        .arg("info")
        .arg("--help")
        .assert()
        .success()
        .stdout(predicate::str::contains(include_str!(
            "assets/info-after-long-help.md"
        )));
}
