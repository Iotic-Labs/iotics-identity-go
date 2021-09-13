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


## Example usage
```toml
# Cargo.toml
[dependencies]
iotics-identity = { git = "ssh://git@github.com/Iotic-Labs/iotics-identity-go.git" }
```
```rust
// main.rs
use iotics_identity;

fn main() {
    let config = iotics_identity::Config{
        resolver_address: "http://localhost:5000".to_string(),
        user_did: "".to_string(),
        agent_did: "".to_string(),
        agent_key_name: "".to_string(),
        agent_name: "".to_string(),
        agent_secret: "".to_string(),
        token_duration: 3600
    };
    let token = iotics_identity::create_agent_auth_token(&config).expect("Creating token failed.");
    let token = format!("bearer {}", token);
    println!("AUTH TOKEN {:?}", token);
    let twin_key_name = "";  // Used to create and recreate the same DID
    let twin_name = "#twin-0";  // Used to identify a document
    let result = iotics_identity::create_twin_did_with_control_delegation(&config, twin_key_name, twin_name)
        .expect("Creating twin DID failed.");
    println!("NEW TWIN DID: {:?}", result);
}
```
