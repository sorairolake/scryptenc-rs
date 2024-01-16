<!--
SPDX-FileCopyrightText: 2022 Shun Sakai

SPDX-License-Identifier: GPL-3.0-or-later
-->

# rscrypt

[![CI][ci-badge]][ci-url]
[![Version][version-badge]][version-url]
![License][license-badge]

**rscrypt** ([`scryptenc-cli`][version-url]) is a command-line utility for
encrypt and decrypt files.

This is a Rust implementation of `scrypt(1)`.

![Screenshot of rscrypt](assets/screenshot.webp)

## Installation

### From source

```sh
cargo install scryptenc-cli
```

### From binaries

The [release page] contains pre-built binaries for Linux, macOS and Windows.

### How to build

Please see [BUILD.adoc].

## Usage

### Basic usage

Encrypt a file:

```sh
rscrypt enc data.txt data.txt.scrypt
```

Decrypt a file:

```sh
rscrypt dec data.txt.scrypt data.txt
```

### Provides information about the encryption parameters

Output as a human-readable string:

```sh
rscrypt info data.txt.scrypt
```

Output:

```text
Parameters used: N = 1024; r = 8; p = 1;
    Decrypting this file requires at least 1 MiB of memory.
```

Output as JSON:

```sh
rscrypt info -j data.txt.scrypt | jq
```

Output:

```json
{
  "N": 1024,
  "r": 8,
  "p": 1
}
```

### Generate shell completion

`--generate-completion` option generates shell completions to stdout.

The following shells are supported:

- `bash`
- `elvish`
- `fish`
- `nushell`
- `powershell`
- `zsh`

Example:

```sh
rscrypt --generate-completion bash > rscrypt.bash
```

## Command-line options

Please see the following:

- [`rscrypt(1)`]
- [`rscrypt-enc(1)`]
- [`rscrypt-dec(1)`]
- [`rscrypt-info(1)`]
- [`rscrypt-help(1)`]

## Changelog

Please see [CHANGELOG.adoc].

## Contributing

Please see [CONTRIBUTING.adoc].

## Acknowledgment

This program is inspired by the [scrypt encryption utility], and built on top
of the [`scryptenc`] crate.

## License

Copyright &copy; 2022&ndash;2024 Shun Sakai (see [AUTHORS.adoc])

1. This program is distributed under the terms of the _GNU General Public
   License v3.0 or later_.
2. Some files are distributed under the terms of the _Creative Commons
   Attribution 4.0 International Public License_.

This project is compliant with version 3.0 of the [_REUSE Specification_]. See
copyright notices of individual files for more details on copyright and
licensing information.

[ci-badge]: https://img.shields.io/github/actions/workflow/status/sorairolake/rscrypt/CI.yaml?branch=develop&label=CI&logo=github&style=for-the-badge
[ci-url]: https://github.com/sorairolake/rscrypt/actions?query=branch%3Adevelop+workflow%3ACI++
[version-badge]: https://img.shields.io/crates/v/scryptenc-cli?style=for-the-badge
[version-url]: https://crates.io/crates/scryptenc-cli
[license-badge]: https://img.shields.io/crates/l/scryptenc-cli?style=for-the-badge
[release page]: https://github.com/sorairolake/rscrypt/releases
[BUILD.adoc]: BUILD.adoc
[`rscrypt(1)`]: https://sorairolake.github.io/rscrypt/book/man/man1/rscrypt.1.html
[`rscrypt-enc(1)`]: https://sorairolake.github.io/rscrypt/book/man/man1/rscrypt-enc.1.html
[`rscrypt-dec(1)`]: https://sorairolake.github.io/rscrypt/book/man/man1/rscrypt-dec.1.html
[`rscrypt-info(1)`]: https://sorairolake.github.io/rscrypt/book/man/man1/rscrypt-info.1.html
[`rscrypt-help(1)`]: https://sorairolake.github.io/rscrypt/book/man/man1/rscrypt-help.1.html
[CHANGELOG.adoc]: CHANGELOG.adoc
[CONTRIBUTING.adoc]: CONTRIBUTING.adoc
[scrypt encryption utility]: https://www.tarsnap.com/scrypt.html
[`scryptenc`]: https://crates.io/crates/scryptenc
[AUTHORS.adoc]: AUTHORS.adoc
[_REUSE Specification_]: https://reuse.software/spec/
