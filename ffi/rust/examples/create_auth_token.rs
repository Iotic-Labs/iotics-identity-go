use iotics_identity;

/// Create an Agent Authentication Token
/// Prerequisites: Create an User, an Agent and a delegation from the User to the Agent
/// See the `create_user_and_agent` example
fn main() {
    // set up all the variables needed
    // NOTE: we don't need the user name, key name or seed for creating agent auth tokens
    let resolver_address = "https://did.stg.iotics.com";

    let user_did = "did:iotics:iotNgaEk7erdRNZfuPczxFXs8M7LuYE8JVDk";

    let agent_did = "did:iotics:iotKEeCnbYs9RM9DoPM9mdCK1At3qm7xvmwP";
    let agent_key_name = "00";
    let agent_name = "#agent-0";
    let agent_seed = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

    // create the config object
    let config = iotics_identity::Config {
        resolver_address: resolver_address.to_string(),
        user_did: user_did.to_string(),
        agent_did: agent_did.to_string(),
        agent_key_name: agent_key_name.to_string(),
        agent_name: agent_name.to_string(),
        agent_secret: agent_seed.to_string(),
        token_duration: 600,
    };

    // create the token
    let token = iotics_identity::create_agent_auth_token(&config).expect("Creating token failed.");
    let token = format!("bearer {}", token);
    println!("AUTH TOKEN {:?}", token);
}
