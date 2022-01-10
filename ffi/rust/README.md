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
    // Creating an User, an Agent and a delegation from the User to the Agent
    let resolver_address = "https://did.stg.iotics.com";

    let user_key_name = "00";
    let user_name = "#user-0";
    let user_seed = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

    let agent_key_name = "00";
    let agent_name = "#agent-0";
    let agent_seed = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

    let delegation_name = "#delegation-0";

    let user_did = iotics_identity::create_user_identity(
        resolver_address,
        user_key_name,
        user_name,
        user_seed,
    )
    .expect("Creating user identity failed.");
    println!("USER DID {:?}", user_did);

    let agent_did = iotics_identity::create_agent_identity(
        resolver_address,
        agent_key_name,
        agent_name,
        agent_seed,
    )
    .expect("Creating agent identity failed.");
    println!("AGENT DID {:?}", agent_did);

    iotics_identity::user_delegates_authentication_to_agent(
        resolver_address,
        &agent_did,
        agent_key_name,
        agent_name,
        agent_seed,
        &user_did,
        user_key_name,
        user_name,
        user_seed,
        delegation_name,
    )
    .expect("Creating the Authentication Delegation from an User to an Agent failed.");
    println!("DELEGATION CREATED");

    // Using the Agent to create an authentication token and a twin
    let config = iotics_identity::Config {
        resolver_address: resolver_address.to_string(),
        user_did: user_did.to_string(),
        agent_did: agent_did.to_string(),
        agent_key_name: agent_key_name.to_string(),
        agent_name: agent_name.to_string(),
        agent_secret: agent_seed.to_string(),
        token_duration: 600,
    };

    let token = iotics_identity::create_agent_auth_token(&config).expect("Creating token failed.");
    let token = format!("bearer {}", token);
    println!("AUTH TOKEN {:?}", token);

    let twin_key_name = "00"; // Used to create and recreate the same DID
    let twin_name = "#twin-0"; // Used to identify a document
    let twin_did =
        iotics_identity::create_twin_did_with_control_delegation(&config, twin_key_name, twin_name)
            .expect("Creating twin DID failed.");
    println!("NEW TWIN DID: {:?}", twin_did);
}
```
