// SPDX-FileCopyrightText: 2022 Shun Sakai
//
// SPDX-License-Identifier: GPL-3.0-or-later

mod utils;

use predicates::prelude::predicate;

#[test]
fn basic_information() {
    utils::command::command()
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
    let command = utils::command::command()
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
    utils::command::command()
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
    utils::command::command()
        .arg("info")
        .arg("-j")
        .arg("data/data.txt.scrypt")
        .assert()
        .success()
        .stdout(predicate::eq(concat!(r#"{"N":1024,"r":8,"p":1}"#, '\n')));
}

#[test]
fn information_if_input_file_is_invalid() {
    utils::command::command()
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
    utils::command::command()
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
    utils::command::command()
        .arg("info")
        .arg("--help")
        .assert()
        .success()
        .stdout(predicate::str::contains(include_str!(
            "assets/info-after-long-help.md"
        )));
}
