<!--
SPDX-FileCopyrightText: 2022 Shun Sakai

SPDX-License-Identifier: Apache-2.0 OR MIT
-->

# scryptenc-rs

[![CI][ci-badge]][ci-url]
[![Version][version-badge]][version-url]
![MSRV][msrv-badge]
[![Docs][docs-badge]][docs-url]
![License][license-badge]

**scryptenc-rs** ([`scryptenc`][version-url]) is an implementation of the
[scrypt encrypted data format].

## Usage

Add this to your `Cargo.toml`:

```toml
[dependencies]
scryptenc = "0.9.6"
```

### Example

```rust
use scryptenc::Params;

let data = b"Hello, world!\n";
let passphrase = "passphrase";

// Encrypt `data` using `passphrase`.
let ciphertext = scryptenc::encrypt(data, passphrase);
assert_ne!(ciphertext, data);

// And extract the scrypt parameters from it.
let params = Params::new(&ciphertext).unwrap();
assert_eq!(params.log_n(), 17);
assert_eq!(params.n(), u64::pow(2, 17));
assert_eq!(params.r(), 8);
assert_eq!(params.p(), 1);

// And decrypt it back.
let plaintext = scryptenc::decrypt(ciphertext, passphrase).unwrap();
assert_eq!(plaintext, data);
```

### Crate features

#### `alloc`

Enables features that require an allocator. This is enabled by default (implied
by `std`).

#### `std`

Enables features that depend on the standard library. This is enabled by
default.

#### `serde`

Enables serialization support for `Params`.

### `no_std` support

This supports `no_std` mode. Disables the `default` feature to enable this.

### Documentation

See the [documentation][docs-url] for more details.

## Minimum supported Rust version

The minimum supported Rust version (MSRV) of this library is v1.74.0.

## Changelog

Please see [CHANGELOG.adoc].

## Contributing

Please see [CONTRIBUTING.adoc].

## License

Copyright &copy; 2022&ndash;2024 Shun Sakai (see [AUTHORS.adoc])

This library is distributed under the terms of either the _Apache License 2.0_
or the _MIT License_.

This project is compliant with version 3.0 of the [_REUSE Specification_]. See
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
[scrypt encrypted data format]: https://github.com/Tarsnap/scrypt/blob/1.3.1/FORMAT
[CHANGELOG.adoc]: CHANGELOG.adoc
[CONTRIBUTING.adoc]: ../../CONTRIBUTING.adoc
[AUTHORS.adoc]: ../../AUTHORS.adoc
[_REUSE Specification_]: https://reuse.software/spec/
