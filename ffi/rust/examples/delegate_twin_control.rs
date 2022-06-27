use iotics_identity;

fn main() {
    // set up all the variables needed
    let resolver_address = "";

    let agent_did = "";
    let agent_key_name = "";
    let agent_name = "";
    let agent_seed = "";

    let private_key_base64 = "";
    let delegation_name = "";

    // convert `private_key_base64` to `private_exponent_hex`
    let private_exponent_hex =
        iotics_identity::get_private_exponent_hex_from_private_key_base64(private_key_base64)
            .expect("failed to convert from private key base64 to private exponent hex");

    // delegate host twin control to an agent by private key base64
    // this can be used for delegating host twin control to an agent by private key base64
    iotics_identity::twin_delegates_control_to_agent_by_private_exponent_hex(
        resolver_address,
        agent_did,
        agent_key_name,
        agent_name,
        agent_seed,
        &private_exponent_hex,
        delegation_name,
    )
    .expect("Failed to delegate control.");
    println!("Control has been delegated succesfully.");
}
