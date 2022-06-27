# Iotics Identity - Foreign Function Interface

A Rust crate for utilising a Go library for Decentralised Identity management through FFI.

## Prerequisites

Install Rust - [official instructions](https://www.rust-lang.org/tools/install) - i.e.:

```shell
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source $HOME/.cargo/env
```

For Linux distros you may need to install the following:

```shell
sudo apt install clang
```

## Development

Build instructions are defined in the [`build.rs`](./build.rs) file and can be called with `cargo build`.

## Usage

```toml
# Cargo.toml
[dependencies]
iotics-identity = { git = "ssh://git@github.com/Iotic-Labs/iotics-identity-go.git" }
```

## Examples

```bash
cargo run --example create_user_and_agent
cargo run --example create_auth_token
cargo run --example create_twin_did
```
