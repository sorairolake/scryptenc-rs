<!--
SPDX-FileCopyrightText: 2022 Shun Sakai

SPDX-License-Identifier: CC-BY-4.0
-->

# Wasm Bindings for scryptenc

[![CI][ci-badge]][ci-url]
[![npm Version][npm-version-badge]][npm-version-url]
[![crates.io Version][crates-version-badge]][crates-version-url]
![MSRV][msrv-badge]
[![Docs][docs-badge]][docs-url]
![License][license-badge]

**scryptenc-wasm** is the Wasm bindings for the [`scryptenc`] crate.

## Usage

### Installation

To install this library:

```sh
npm install @sorairolake/scryptenc-wasm
```

### Build

You will need [`wasm-pack`] to build this crate.

```sh
wasm-pack build
```

This will generate build artifacts in the `pkg` directory.

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
[npm-version-badge]: https://img.shields.io/npm/v/%40sorairolake%2Fscryptenc-wasm?style=for-the-badge&logo=npm
[npm-version-url]: https://www.npmjs.com/package/@sorairolake/scryptenc-wasm
[crates-version-badge]: https://img.shields.io/crates/v/scryptenc-wasm?style=for-the-badge&logo=rust
[crates-version-url]: https://crates.io/crates/scryptenc-wasm
[msrv-badge]: https://img.shields.io/crates/msrv/scryptenc-wasm?style=for-the-badge&logo=rust
[docs-badge]: https://img.shields.io/docsrs/scryptenc-wasm?style=for-the-badge&logo=docsdotrs&label=Docs.rs
[docs-url]: https://docs.rs/scryptenc-wasm
[license-badge]: https://img.shields.io/crates/l/scryptenc-wasm?style=for-the-badge
[`scryptenc`]: https://crates.io/crates/scryptenc
[`wasm-pack`]: https://rustwasm.github.io/wasm-pack/
[CHANGELOG.adoc]: https://github.com/sorairolake/scryptenc-rs/blob/develop/crates/wasm/CHANGELOG.adoc
[CONTRIBUTING.adoc]: https://github.com/sorairolake/scryptenc-rs/blob/develop/CONTRIBUTING.adoc
[AUTHORS.adoc]: https://github.com/sorairolake/scryptenc-rs/blob/develop/AUTHORS.adoc
[_REUSE Specification_]: https://reuse.software/spec-3.3/
