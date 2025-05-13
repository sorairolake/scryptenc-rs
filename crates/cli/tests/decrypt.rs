// SPDX-FileCopyrightText: 2022 Shun Sakai
//
// SPDX-License-Identifier: GPL-3.0-or-later

mod utils;

use predicates::prelude::predicate;

#[test]
fn basic_decrypt() {
    utils::command::command()
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
    let command = utils::command::command()
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
    let command = utils::command::command()
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
    utils::command::command()
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
    utils::command::command()
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
    utils::command::command()
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
    utils::command::command()
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
    utils::command::command()
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
    utils::command::command()
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
    utils::command::command()
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
    utils::command::command()
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
    utils::command::command()
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
    utils::command::command()
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
    utils::command::command()
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
    utils::command::command()
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
            r#"failed to parse "NaN" in the "friendly" format"#,
        ));
    utils::command::command()
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
            r#"failed to parse "1" in the "friendly" format"#,
        ));
    utils::command::command()
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
            r#"failed to parse "1a" in the "friendly" format"#,
        ));
    utils::command::command()
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
            r#"failed to parse "10000000000000y" in the "friendly" format"#,
        ));
}

#[test]
fn validate_conflicts_if_reading_from_stdin_for_decrypt_command() {
    utils::command::command()
        .arg("dec")
        .arg("--passphrase-from-stdin")
        .arg("-")
        .write_stdin("passphrase")
        .assert()
        .failure()
        .stderr(predicate::str::ends_with(
            "cannot read both passphrase and input data from standard input\n",
        ));
}

#[test]
fn decrypt_if_input_file_is_invalid() {
    utils::command::command()
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
    utils::command::command()
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
    utils::command::command()
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
