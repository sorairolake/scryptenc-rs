# SPDX-FileCopyrightText: 2022 Shun Sakai
#
# SPDX-License-Identifier: Apache-2.0 OR MIT

alias lint := clippy

# Run default recipe
@_default:
    just -l

# Build packages
@build:
    cargo build --workspace

# Remove generated artifacts
@clean:
    cargo clean

# Check packages
@check:
    cargo check --workspace

# Run tests
@test:
    cargo test -p scryptenc -p scryptenc-cli

# Run benchmarks
@bench:
    cargo +nightly bench -p scryptenc

# Run the formatter
@fmt:
    cargo fmt --all

# Run the formatter with options
@fmt-with-options:
    cargo +nightly fmt --all

# Run the linter
@clippy:
    cargo clippy --workspace -- -D warnings

# Apply lint suggestions
@clippy-fix:
    cargo +nightly clippy --workspace --fix --allow-dirty --allow-staged -- -D warnings

# Build the library package documentation
@doc $RUSTDOCFLAGS="--cfg docsrs":
    cargo +nightly doc -p scryptenc --all-features

# Run tests for the Wasm bindings
@wasm-test:
    wasm-pack test --node crates/wasm

# Build examples for the Wasm bindings
@build-wasm-examples:
    wasm-pack build -t deno crates/wasm

# Run `deno fmt`
@fmt-wasm-examples:
    deno fmt crates/wasm/examples/*.ts

# Run `deno lint`
@lint-wasm-examples:
    deno lint crates/wasm/examples/*.ts

# Run `deno check`
@type-check-wasm-examples:
    deno check crates/wasm/examples/*.ts

# Run the linter for GitHub Actions workflow files
@lint-github-actions:
    actionlint -verbose

# Run the formatter for the README
@fmt-readme:
    npx prettier -w crates/*/README.md

# Build the book
@build-book:
    npx antora antora-playbook.yml

# Build the Wasm bindings
[working-directory("crates/wasm")]
@build-wasm $CARGO_PROFILE_RELEASE_CODEGEN_UNITS="1" $CARGO_PROFILE_RELEASE_STRIP="true":
    wasm-pack build -s sorairolake -t nodejs --release

# Publish the Wasm bindings
[working-directory("crates/wasm")]
@publish-wasm: build-wasm
    wasm-pack publish -a public

# Increment the version of the library
@bump-lib part:
    bump-my-version bump --config-file .bumpversion-lib.toml {{ part }}
    cargo set-version --bump {{ part }} -p scryptenc

# Increment the version of the command-line utility
@bump-cli part:
    bump-my-version bump --config-file .bumpversion-cli.toml {{ part }}
    cargo set-version --bump {{ part }} -p scryptenc-cli

# Increment the version of the Wasm bindings
@bump-wasm part:
    bump-my-version bump --config-file .bumpversion-wasm.toml {{ part }}
    cargo set-version --bump {{ part }} -p scryptenc-wasm
