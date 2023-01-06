# scryptenc-rs

[![CI][ci-badge]][ci-url]
[![Version][version-badge]][version-url]
[![Docs][docs-badge]][docs-url]
![License][license-badge]

**scryptenc-rs** ([`scryptenc`][version-url]) is an implementation of the
scrypt encrypted data format.

The format is defined [here][specification-url].

## Usage

Add this to your `Cargo.toml`:

```toml
[dependencies]
scryptenc = "0.4.1"
```

### Crate features

#### `std`

Enables features that depend on the standard library.
This is enabled by default.

### `no_std` support

This supports `no_std` mode.
Disables the `default` feature to enable this.

### Documentation

See the [documentation][docs-url] for more details.

## Minimum supported Rust version

The minimum supported Rust version (MSRV) of this library is v1.57.0 or later.

## Changelog

Please see [CHANGELOG.adoc](CHANGELOG.adoc).

## Contributing

Please see [CONTRIBUTING.adoc](CONTRIBUTING.adoc).

## License

Copyright &copy; 2022&ndash;2023 Shun Sakai (see [AUTHORS.adoc](AUTHORS.adoc))

This library is distributed under the terms of either the _Apache License 2.0_
or the _MIT License_.

See [COPYRIGHT](COPYRIGHT), [LICENSE-APACHE](LICENSE-APACHE) and
[LICENSE-MIT](LICENSE-MIT) for more details.

[ci-badge]: https://github.com/sorairolake/scryptenc-rs/workflows/CI/badge.svg
[ci-url]: https://github.com/sorairolake/scryptenc-rs/actions?query=workflow%3ACI
[version-badge]: https://img.shields.io/crates/v/scryptenc
[version-url]: https://crates.io/crates/scryptenc
[docs-badge]: https://img.shields.io/docsrs/scryptenc
[docs-url]: https://docs.rs/scryptenc
[license-badge]: https://img.shields.io/crates/l/scryptenc
[specification-url]: https://github.com/Tarsnap/scrypt/blob/d7a543fb19dca17688e34947aee4558a94200877/FORMAT
