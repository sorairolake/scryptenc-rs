<!--
SPDX-FileCopyrightText: 2022 Shun Sakai

SPDX-License-Identifier: CC-BY-4.0
-->

# scryptenc-rs

[![CI][ci-badge]][ci-url]
[![Version][version-badge]][version-url]
![MSRV][msrv-badge]
[![Docs][docs-badge]][docs-url]
![License][license-badge]

**scryptenc-rs** ([`scryptenc`][version-url]) is an implementation of the
[scrypt encrypted data format].

This crate supports version 1 of the scrypt format.

## Usage

Run the following command in your project directory:

```sh
cargo add scryptenc
```

### Crate features

#### `alloc`

Enables features that require an allocator. This is enabled by default (implied
by `std`).

#### `serde`

Enables serialization support for `Params`.

#### `std`

Enables features that depend on the standard library. This is enabled by
default.

### `no_std` support

This supports `no_std` mode. Disables the `default` feature to enable this.

### Documentation

See the [documentation][docs-url] for more details.

## Minimum supported Rust version

The minimum supported Rust version (MSRV) of this library is v1.85.0.

## Source code

The upstream repository is available at
<https://github.com/sorairolake/scryptenc-rs.git>.

## Changelog

Please see [CHANGELOG.adoc].

## Contributing

Please see [CONTRIBUTING.adoc].

## Home page

<https://sorairolake.github.io/scryptenc-rs/>

## License

Copyright (C) 2022 Shun Sakai (see [AUTHORS.adoc])

This library is distributed under the terms of either the _Apache License 2.0_
or the _MIT License_.

This project is compliant with version 3.3 of the [_REUSE Specification_]. See
copyright notices of individual files for more details on copyright and
licensing information.

[ci-badge]: https://img.shields.io/github/actions/workflow/status/sorairolake/scryptenc-rs/CI.yaml?branch=develop&style=for-the-badge&logo=github&label=CI
[ci-url]: https://github.com/sorairolake/scryptenc-rs/actions?query=branch%3Adevelop+workflow%3ACI++
[version-badge]: https://img.shields.io/crates/v/scryptenc?style=for-the-badge&logo=rust
[version-url]: https://crates.io/crates/scryptenc
[msrv-badge]: https://img.shields.io/crates/msrv/scryptenc?style=for-the-badge&logo=rust
[docs-badge]: https://img.shields.io/docsrs/scryptenc?style=for-the-badge&logo=docsdotrs&label=Docs.rs
[docs-url]: https://docs.rs/scryptenc
[license-badge]: https://img.shields.io/crates/l/scryptenc?style=for-the-badge
[scrypt encrypted data format]: https://github.com/Tarsnap/scrypt/blob/1.3.3/FORMAT
[CHANGELOG.adoc]: CHANGELOG.adoc
[CONTRIBUTING.adoc]: ../../CONTRIBUTING.adoc
[AUTHORS.adoc]: ../../AUTHORS.adoc
[_REUSE Specification_]: https://reuse.software/spec-3.3/
