// SPDX-FileCopyrightText: 2022 Shun Sakai
//
// SPDX-License-Identifier: GPL-3.0-or-later

mod utils;

use predicates::prelude::predicate;

#[test]
fn basic_encrypt() {
    utils::command::command()
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
fn infer_subcommand_name_for_encrypt_command() {
    utils::command::command()
        .arg("e")
        .arg("-V")
        .assert()
        .success()
        .stdout(predicate::str::contains("rscrypt-enc"));
}

#[test]
fn encrypt_if_non_existent_input_file() {
    let command = utils::command::command()
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
    let command = utils::command::command()
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
    utils::command::command()
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
    utils::command::command()
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
    utils::command::command()
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
    utils::command::command()
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
    utils::command::command()
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
    utils::command::command()
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
    utils::command::command()
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
    utils::command::command()
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
    utils::command::command()
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
    utils::command::command()
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
    utils::command::command()
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
    utils::command::command()
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
            r#"failed to parse "NaN" in the "friendly" format"#,
        ));
    utils::command::command()
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
            r#"failed to parse "1" in the "friendly" format"#,
        ));
    utils::command::command()
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
            r#"failed to parse "1a" in the "friendly" format"#,
        ));
    utils::command::command()
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
            r#"failed to parse "10000000000000y" in the "friendly" format"#,
        ));
}

#[test]
fn validate_parameters_group_for_encrypt_command() {
    utils::command::command()
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
    utils::command::command()
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
    utils::command::command()
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
    utils::command::command()
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
    utils::command::command()
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
    utils::command::command()
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
    utils::command::command()
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
    utils::command::command()
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
    utils::command::command()
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
    utils::command::command()
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
            "cannot read both passphrase and input data from standard input\n",
        ));
}

#[test]
fn encrypt_verbose() {
    utils::command::command()
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
