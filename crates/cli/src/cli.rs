// SPDX-FileCopyrightText: 2022 Shun Sakai
//
// SPDX-License-Identifier: GPL-3.0-or-later

use std::{
    fmt,
    io::{self, Write},
    ops::Deref,
    path::PathBuf,
    str::FromStr,
    time::Duration,
};

use anyhow::anyhow;
use clap::{
    value_parser, ArgGroup, Args, CommandFactory, Parser, Subcommand, ValueEnum, ValueHint,
};
use clap_complete::Generator;
use fraction::{Fraction, Zero};

const LONG_VERSION: &str = concat!(
    env!("CARGO_PKG_VERSION"),
    '\n',
    "Copyright (C) 2022 Shun Sakai\n",
    '\n',
    "This program is distributed under the terms of the GNU General Public License\n",
    "v3.0 or later.\n",
    '\n',
    "This is free software: you are free to change and redistribute it. There is NO\n",
    "WARRANTY, to the extent permitted by law.\n",
    '\n',
    "Report bugs to <https://github.com/sorairolake/scryptenc-rs/issues>."
);

const AFTER_LONG_HELP: &str = "See `rscrypt(1)` for more details.";

const ENC_AFTER_LONG_HELP: &str = "See `rscrypt-enc(1)` for more details.";

const DEC_AFTER_LONG_HELP: &str = "See `rscrypt-dec(1)` for more details.";

const INFO_AFTER_LONG_HELP: &str = "See `rscrypt-info(1)` for more details.";

#[derive(Debug, Parser)]
#[command(
    name("rscrypt"),
    version,
    long_version(LONG_VERSION),
    about,
    max_term_width(100),
    propagate_version(true),
    after_long_help(AFTER_LONG_HELP),
    arg_required_else_help(true),
    args_conflicts_with_subcommands(true)
)]
pub struct Opt {
    /// Generate shell completion.
    ///
    /// The completion is output to standard output.
    #[arg(long, value_enum, value_name("SHELL"))]
    pub generate_completion: Option<Shell>,

    #[command(subcommand)]
    pub command: Option<Command>,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    /// Encrypt files.
    #[command(name("enc"), after_long_help(ENC_AFTER_LONG_HELP))]
    Encrypt(Encrypt),

    /// Decrypt files.
    #[command(name("dec"), after_long_help(DEC_AFTER_LONG_HELP))]
    Decrypt(Decrypt),

    /// Provides information about the encryption parameters.
    #[command(name("info"), after_long_help(INFO_AFTER_LONG_HELP))]
    Information(Information),
}

#[derive(Args, Debug)]
#[allow(clippy::struct_excessive_bools)]
#[command(
    group(ArgGroup::new("passphrase")),
    group(
        ArgGroup::new("resources")
            .multiple(true)
            .conflicts_with("force")
            .conflicts_with("parameters")
    ),
    group(ArgGroup::new("parameters").multiple(true))
)]
pub struct Encrypt {
    /// Force the encryption to proceed even if it requires an excessive amount
    /// of resources.
    #[arg(short, long, requires("parameters"))]
    pub force: bool,

    /// Use at most the specified bytes of RAM to compute the derived key.
    #[arg(short('M'), long, value_name("BYTE"), group("resources"))]
    pub max_memory: Option<Byte>,

    /// Use at most the specified fraction of the available RAM to compute the
    /// derived key.
    #[arg(
        short,
        long,
        default_value("0.125"),
        value_name("RATE"),
        group("resources")
    )]
    pub max_memory_fraction: Rate,

    /// Use at most the specified duration of CPU time to compute the derived
    /// key.
    #[arg(
        short('t'),
        long,
        default_value("5s"),
        value_name("DURATION"),
        group("resources")
    )]
    pub max_time: Time,

    /// Set the work parameter N to 2^<VALUE>.
    #[arg(
        value_parser(value_parser!(u8).range(10..=40)),
        long,
        requires("r"),
        requires("p"),
        value_name("VALUE"),
        group("parameters")
    )]
    pub log_n: Option<u8>,

    /// Set the work parameter r.
    #[arg(
        value_parser(value_parser!(u32).range(1..=32)),
        short,
        requires("log_n"),
        requires("p"),
        value_name("VALUE"),
        group("parameters")
    )]
    pub r: Option<u32>,

    /// Set the work parameter p.
    #[arg(
        value_parser(value_parser!(u32).range(1..=32)),
        short,
        requires("log_n"),
        requires("r"),
        value_name("VALUE"),
        group("parameters")
    )]
    pub p: Option<u32>,

    /// Read the passphrase from /dev/tty.
    ///
    /// This is the default behavior.
    #[arg(long, group("passphrase"))]
    pub passphrase_from_tty: bool,

    /// Read the passphrase from standard input.
    #[arg(long, group("passphrase"))]
    pub passphrase_from_stdin: bool,

    /// Read the passphrase from /dev/tty only once.
    #[arg(long, group("passphrase"))]
    pub passphrase_from_tty_once: bool,

    /// Read the passphrase from the environment variable.
    ///
    /// Note that storing a passphrase in an environment variable can be a
    /// security risk.
    #[arg(long, value_name("VAR"), group("passphrase"))]
    pub passphrase_from_env: Option<String>,

    /// Read the passphrase from the file.
    ///
    /// Note that storing a passphrase in a file can be a security risk.
    #[arg(
        long,
        value_name("FILE"),
        value_hint(ValueHint::FilePath),
        group("passphrase")
    )]
    pub passphrase_from_file: Option<PathBuf>,

    /// Print encryption parameters and resource limits.
    #[arg(short, long)]
    pub verbose: bool,

    /// Input file.
    ///
    /// If "-" is specified, data will be read from standard input.
    #[arg(value_name("INFILE"), value_hint(ValueHint::FilePath))]
    pub input: PathBuf,

    /// Output file.
    ///
    /// If [OUTFILE] is not specified, the result will be write to standard
    /// output.
    #[arg(value_name("OUTFILE"), value_hint(ValueHint::FilePath))]
    pub output: Option<PathBuf>,
}

#[derive(Args, Debug)]
#[allow(clippy::struct_excessive_bools)]
#[command(
    group(ArgGroup::new("passphrase")),
    group(ArgGroup::new("resources").multiple(true).conflicts_with("force"))
)]
pub struct Decrypt {
    /// Force the decryption to proceed even if it requires an excessive amount
    /// of resources.
    #[arg(short, long)]
    pub force: bool,

    /// Use at most the specified bytes of RAM to compute the derived key.
    #[arg(short('M'), long, value_name("BYTE"), group("resources"))]
    pub max_memory: Option<Byte>,

    /// Use at most the specified fraction of the available RAM to compute the
    /// derived key.
    #[arg(
        short,
        long,
        default_value("0.5"),
        value_name("RATE"),
        group("resources")
    )]
    pub max_memory_fraction: Rate,

    /// Use at most the specified duration of CPU time to compute the derived
    /// key.
    #[arg(
        short('t'),
        long,
        default_value("300s"),
        value_name("DURATION"),
        group("resources")
    )]
    pub max_time: Time,

    /// Read the passphrase from /dev/tty.
    ///
    /// This is the default behavior.
    #[arg(long, group("passphrase"))]
    pub passphrase_from_tty: bool,

    /// Read the passphrase from standard input.
    #[arg(long, group("passphrase"))]
    pub passphrase_from_stdin: bool,

    /// Read the passphrase from the environment variable.
    ///
    /// Note that storing a passphrase in an environment variable can be a
    /// security risk.
    #[arg(long, value_name("VAR"), group("passphrase"))]
    pub passphrase_from_env: Option<String>,

    /// Read the passphrase from the file.
    ///
    /// Note that storing a passphrase in a file can be a security risk.
    #[arg(
        long,
        value_name("FILE"),
        value_hint(ValueHint::FilePath),
        group("passphrase")
    )]
    pub passphrase_from_file: Option<PathBuf>,

    /// Print encryption parameters and resource limits.
    #[arg(short, long)]
    pub verbose: bool,

    /// Input file.
    ///
    /// If "-" is specified, data will be read from standard input.
    #[arg(value_name("INFILE"), value_hint(ValueHint::FilePath))]
    pub input: PathBuf,

    /// Output file.
    ///
    /// If [OUTFILE] is not specified, the result will be write to standard
    /// output.
    #[arg(value_name("OUTFILE"), value_hint(ValueHint::FilePath))]
    pub output: Option<PathBuf>,
}

#[derive(Args, Debug)]
pub struct Information {
    /// Output the encryption parameters as JSON.
    #[cfg(feature = "json")]
    #[arg(short, long)]
    pub json: bool,

    /// Input file.
    ///
    /// If "-" is specified, data will be read from standard input.
    #[arg(value_name("FILE"), value_hint(ValueHint::FilePath))]
    pub input: PathBuf,
}

impl Opt {
    /// Generates shell completion and print it.
    pub fn print_completion(gen: impl Generator) {
        clap_complete::generate(
            gen,
            &mut Self::command(),
            Self::command().get_name(),
            &mut io::stdout(),
        );
    }
}

#[derive(Clone, Debug, ValueEnum)]
#[allow(clippy::doc_markdown)]
#[value(rename_all = "lower")]
pub enum Shell {
    /// Bash.
    Bash,

    /// Elvish.
    Elvish,

    /// fish.
    Fish,

    /// Nushell.
    Nushell,

    #[allow(clippy::enum_variant_names)]
    /// PowerShell.
    PowerShell,

    /// Zsh.
    Zsh,
}

impl Generator for Shell {
    fn file_name(&self, name: &str) -> String {
        match self {
            Self::Bash => clap_complete::Shell::Bash.file_name(name),
            Self::Elvish => clap_complete::Shell::Elvish.file_name(name),
            Self::Fish => clap_complete::Shell::Fish.file_name(name),
            Self::Nushell => clap_complete_nushell::Nushell.file_name(name),
            Self::PowerShell => clap_complete::Shell::PowerShell.file_name(name),
            Self::Zsh => clap_complete::Shell::Zsh.file_name(name),
        }
    }

    fn generate(&self, cmd: &clap::Command, buf: &mut dyn Write) {
        match self {
            Self::Bash => clap_complete::Shell::Bash.generate(cmd, buf),
            Self::Elvish => clap_complete::Shell::Elvish.generate(cmd, buf),
            Self::Fish => clap_complete::Shell::Fish.generate(cmd, buf),
            Self::Nushell => clap_complete_nushell::Nushell.generate(cmd, buf),
            Self::PowerShell => clap_complete::Shell::PowerShell.generate(cmd, buf),
            Self::Zsh => clap_complete::Shell::Zsh.generate(cmd, buf),
        }
    }
}

/// Amount of RAM.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Byte(byte_unit::Byte);

impl Deref for Byte {
    type Target = byte_unit::Byte;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl FromStr for Byte {
    type Err = anyhow::Error;

    fn from_str(bytes: &str) -> anyhow::Result<Self> {
        match byte_unit::Byte::from_str(bytes) {
            Ok(b) if b < byte_unit::Byte::MEBIBYTE => {
                Err(anyhow!("amount of RAM is less than 1 MiB"))
            }
            Err(err) => Err(anyhow!("amount of RAM is not a valid value: {err}")),
            Ok(b) => Ok(Self(b)),
        }
    }
}

/// Fraction of the available RAM.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Rate(Fraction);

impl Deref for Rate {
    type Target = Fraction;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl FromStr for Rate {
    type Err = anyhow::Error;

    fn from_str(rate: &str) -> anyhow::Result<Self> {
        match Fraction::from_str(rate) {
            Ok(r) if r == Fraction::zero() => Err(anyhow!("fraction is 0")),
            Ok(r) if r > Fraction::from(0.5) => Err(anyhow!("fraction is more than 0.5")),
            Err(err) => Err(anyhow!("fraction is not a valid number: {err}")),
            Ok(r) => Ok(Self(r)),
        }
    }
}

/// CPU time.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct Time(Duration);

impl fmt::Debug for Time {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

impl Deref for Time {
    type Target = Duration;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl FromStr for Time {
    type Err = anyhow::Error;

    fn from_str(duration: &str) -> anyhow::Result<Self> {
        match humantime::Duration::from_str(duration) {
            Ok(d) => Ok(Self(*d)),
            Err(err) => Err(anyhow!("time is not a valid value: {err}")),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn verify_app() {
        Opt::command().debug_assert();
    }

    #[test]
    fn file_name_shell() {
        assert_eq!(Shell::Bash.file_name("rscrypt"), "rscrypt.bash");
        assert_eq!(Shell::Elvish.file_name("rscrypt"), "rscrypt.elv");
        assert_eq!(Shell::Fish.file_name("rscrypt"), "rscrypt.fish");
        assert_eq!(Shell::Nushell.file_name("rscrypt"), "rscrypt.nu");
        assert_eq!(Shell::PowerShell.file_name("rscrypt"), "_rscrypt.ps1");
        assert_eq!(Shell::Zsh.file_name("rscrypt"), "_rscrypt");
    }

    #[test]
    fn deref_byte() {
        assert_eq!(*Byte(byte_unit::Byte::MEBIBYTE), byte_unit::Byte::MEBIBYTE);
    }

    #[test]
    fn from_str_byte() {
        assert_eq!(
            Byte::from_str("1048576 B").unwrap(),
            Byte(byte_unit::Byte::MEBIBYTE)
        );
        assert_eq!(
            Byte::from_str("1048576").unwrap(),
            Byte(byte_unit::Byte::MEBIBYTE)
        );
        assert_eq!(
            Byte::from_str("1024 KiB").unwrap(),
            Byte(byte_unit::Byte::MEBIBYTE)
        );
        assert_eq!(
            Byte::from_str("1.0 MiB").unwrap(),
            Byte(byte_unit::Byte::MEBIBYTE)
        );
        assert_eq!(
            Byte::from_str("1MiB").unwrap(),
            Byte(byte_unit::Byte::MEBIBYTE)
        );
    }

    #[test]
    fn from_str_byte_with_invalid_unit() {
        assert!(Byte::from_str("1048576 A")
            .unwrap_err()
            .to_string()
            .contains("the character 'A' is incorrect"));
        assert!(Byte::from_str("1.0LiB")
            .unwrap_err()
            .to_string()
            .contains("the character 'L' is incorrect"));
    }

    #[test]
    fn from_str_byte_with_nan() {
        assert!(Byte::from_str("n B")
            .unwrap_err()
            .to_string()
            .contains("the character 'n' is not a number"));
        assert!(Byte::from_str("n")
            .unwrap_err()
            .to_string()
            .contains("the character 'n' is not a number"));
        assert!(Byte::from_str("nMiB")
            .unwrap_err()
            .to_string()
            .contains("the character 'n' is not a number"));
    }

    #[test]
    fn from_str_byte_if_out_of_range() {
        assert!(Byte::from_str("1023.99 KiB").is_err());
        assert!(Byte::from_str("16.01 EiB").is_err());
    }

    #[test]
    fn deref_rate() {
        assert_eq!(*Rate(Fraction::from(0.5)), Fraction::from(0.5));
    }

    #[test]
    fn from_str_rate() {
        assert_eq!(Rate::from_str("0.5").unwrap(), Rate(Fraction::from(0.5)));
        assert_eq!(Rate::from_str("+0.5").unwrap(), Rate(Fraction::from(0.5)));
        assert_eq!(Rate::from_str("1/2").unwrap(), Rate(Fraction::from(0.5)));
    }

    #[test]
    fn from_str_rate_with_invalid_fraction() {
        assert!(Rate::from_str("RATE")
            .unwrap_err()
            .to_string()
            .contains("Could not parse integer"));
    }

    #[test]
    fn from_str_rate_if_out_of_range() {
        assert!(Rate::from_str("0")
            .unwrap_err()
            .to_string()
            .contains("fraction is 0"));
        assert!(Rate::from_str("0.51")
            .unwrap_err()
            .to_string()
            .contains("fraction is more than 0.5"));
    }

    #[test]
    fn debug_time() {
        assert_eq!(format!("{:?}", Time(Duration::from_secs(5))), "5s");
    }

    #[test]
    fn deref_time() {
        assert_eq!(*Time(Duration::from_secs(5)), Duration::from_secs(5));
    }

    #[test]
    fn from_str_time() {
        assert_eq!(
            Time::from_str("10s").unwrap(),
            Time(Duration::from_secs(10))
        );
    }

    #[test]
    fn from_str_time_with_invalid_time() {
        assert!(Time::from_str("NaN")
            .unwrap_err()
            .to_string()
            .contains("expected number at 0"));
        assert!(Time::from_str("1")
            .unwrap_err()
            .to_string()
            .contains("time unit needed"));
        assert!(Time::from_str("1a")
            .unwrap_err()
            .to_string()
            .contains(r#"unknown time unit "a""#));
        assert!(Time::from_str("10000000000000y")
            .unwrap_err()
            .to_string()
            .contains("number is too large"));
    }
}
