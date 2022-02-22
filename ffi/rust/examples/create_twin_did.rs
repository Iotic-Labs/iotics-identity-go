use iotics_identity;

/// Create a Twin DID
/// Prerequisites: Create an User, an Agent and a delegation from the User to the Agent
/// See the `create_user_and_agent` example
fn main() {
    // set up all the variables needed
    let resolver_address = "https://did.stg.iotics.com";

    let user_did = "did:iotics:iotNgaEk7erdRNZfuPczxFXs8M7LuYE8JVDk";

    let agent_did = "did:iotics:iotKEeCnbYs9RM9DoPM9mdCK1At3qm7xvmwP";
    let agent_key_name = "00";
    let agent_name = "#agent-0";
    let agent_seed = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

    let twin_key_name = "00"; // used to create and recreate the same DID
    let twin_name = "#twin-0"; // used to identify a document

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

    // create the twin did
    let twin_did =
        iotics_identity::create_twin_did_with_control_delegation(&config, twin_key_name, twin_name)
            .expect("Creating twin DID failed.");
    println!("NEW TWIN DID: {:?}", twin_did);
}
