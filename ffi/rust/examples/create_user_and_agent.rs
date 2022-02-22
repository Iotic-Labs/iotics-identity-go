use iotics_identity;

/// Create an User, an Agent and a delegation from the User to the Agent
fn main() {
    // set up all the variables needed
    let resolver_address = "https://did.stg.iotics.com";

    let user_key_name = "00";
    let user_name = "#user-0";
    let user_seed = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

    let agent_key_name = "00";
    let agent_name = "#agent-0";
    let agent_seed = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

    let delegation_name = "#delegation-0";

    // create the user
    let user_did = iotics_identity::create_user_identity(
        resolver_address,
        user_key_name,
        user_name,
        user_seed,
    )
    .expect("Creating user identity failed.");
    println!("USER DID {:?}", user_did);

    // create the agent
    let agent_did = iotics_identity::create_agent_identity(
        resolver_address,
        agent_key_name,
        agent_name,
        agent_seed,
    )
    .expect("Creating agent identity failed.");
    println!("AGENT DID {:?}", agent_did);

    // create the auth delegation
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
}
