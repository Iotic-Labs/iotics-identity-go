//! Foreign Function Interface  library utilising "wrapped"
//! [iotics-identity-go](../../../../../README.md).
//!
//! [`ffi_wrapper`] is automatically generated by
//! [`rust-bindgen`](https://docs.rs/bindgen/)
//! during the build.
use libc;

use std::ffi::{CStr, CString, NulError};
use std::str::Utf8Error;

use thiserror::Error;

#[allow(
    non_camel_case_types,
    non_upper_case_globals,
    improper_ctypes,
    non_snake_case,
    clippy::missing_safety_doc,
    clippy::redundant_static_lifetimes
)]
pub mod ffi_wrapper;

/// Struct containing all the required secrets and parameters for working with this library.
#[derive(Debug, Clone)]
pub struct Config {
    pub resolver_address: String,
    pub user_did: String,
    pub agent_did: String,
    pub agent_key_name: String,
    pub agent_name: String,
    pub agent_secret: String,
    pub token_duration: i64,
}

/// A common error type used across this library.
#[derive(Error, Debug)]
pub enum IdentityLibError {
    #[error(transparent)]
    Utf8Error(#[from] Utf8Error),
    #[error(transparent)]
    NulError(#[from] NulError),
    #[error("FFI library error message: `{0}`.")]
    Message(String),
}

/// Creates an User Identity
///
/// Params:
/// - [`resolver_address`][`str`] - The HTTPS address of the resolver where this Identity should reside.
/// - [`key_name`][`str`] - Will show up in the public document. Will be used as part of the DID hash.
/// - [`twin_name`][`str`] - Will show up in the public document. Not used as part of the DID hash.
/// - [`seed`][`str`] - The seed used to create and later possibly re-create this identity.
///
/// Returns:
/// - [`Result`][Result::Ok] with [`String`] if generating a DID succeeds.
/// - [`Result`][Result::Err] with [`IdentityLibError`] if generating a DID fails.
pub fn create_user_identity(
    resolver_address: &str,
    key_name: &str,
    name: &str,
    seed: &str,
) -> Result<String, IdentityLibError> {
    let result = unsafe {
        let resolver_address = CStringRaw::new(resolver_address)?;
        let key_name = CStringRaw::new(key_name)?;
        let name = CStringRaw::new(name)?;
        let seed = CStringRaw::new(seed)?;

        ffi_wrapper::CreateUserIdentity(
            resolver_address.as_raw()?,
            key_name.as_raw()?,
            name.as_raw()?,
            seed.as_raw()?,
        )
    };

    match result.r1.is_null() {
        true => {
            let token = unsafe { CStr::from_ptr(result.r0) }.to_str()?;
            Ok(token.to_string())
        }
        false => {
            let error = unsafe { CStr::from_ptr(result.r1) }.to_str()?;
            Err(IdentityLibError::Message(error.to_string()))
        }
    }
}

/// Creates an Agent Identity
///
/// Params:
/// - [`resolver_address`][`str`] - The HTTPS address of the resolver where this Identity should reside.
/// - [`key_name`][`str`] - Will show up in the public document. Will be used as part of the DID hash.
/// - [`twin_name`][`str`] - Will show up in the public document. Not used as part of the DID hash.
/// - [`seed`][`str`] - The seed used to create and later possibly re-create this identity.
///
/// Returns:
/// - [`Result`][Result::Ok] with [`String`] if generating a DID succeeds.
/// - [`Result`][Result::Err] with [`IdentityLibError`] if generating a DID fails.
pub fn create_agent_identity(
    resolver_address: &str,
    key_name: &str,
    name: &str,
    seed: &str,
) -> Result<String, IdentityLibError> {
    let result = unsafe {
        let resolver_address = CStringRaw::new(resolver_address)?;
        let key_name = CStringRaw::new(key_name)?;
        let name = CStringRaw::new(name)?;
        let seed = CStringRaw::new(seed)?;

        ffi_wrapper::CreateAgentIdentity(
            resolver_address.as_raw()?,
            key_name.as_raw()?,
            name.as_raw()?,
            seed.as_raw()?,
        )
    };

    match result.r1.is_null() {
        true => {
            let token = unsafe { CStr::from_ptr(result.r0) }.to_str()?;
            Ok(token.to_string())
        }
        false => {
            let error = unsafe { CStr::from_ptr(result.r1) }.to_str()?;
            Err(IdentityLibError::Message(error.to_string()))
        }
    }
}

/// Creates an Authentication Delegation from an User to an Agent
///
/// Params:
/// - [`resolver_address`][`str`] - The HTTPS address of the resolver where this Identity should reside.
/// - [`agent_did`][`str`] - The Agent DID.
/// - [`agent_key_name`][`str`] - The Agent Key Name. As it was defined when the Agent Identity was created.
/// - [`agent_twin_name`][`str`] - The Agent Name. As it was defined when the Agent Identity was created.
/// - [`agent_seed`][`str`] - The Agent Seed. As it was defined when the Agent Identity was created.
/// - [`user_did`][`str`] - The User DID.
/// - [`user_key_name`][`str`] - The User Key Name. As it was defined when the User Identity was created.
/// - [`user_twin_name`][`str`] - The User Name. As it was defined when the User Identity was created.
/// - [`user_seed`][`str`] - The User Seed. As it was defined when the user Identity was created.
/// - [`delegation_name`][`str`] - The Name of the delegation.
///
/// Returns:
/// - [`Result`][Result::Ok] with [`String`] if generating a DID succeeds.
/// - [`Result`][Result::Err] with [`IdentityLibError`] if generating a DID fails.
#[allow(clippy::too_many_arguments)]
pub fn user_delegates_authentication_to_agent(
    resolver_address: &str,
    agent_did: &str,
    agent_key_name: &str,
    agent_name: &str,
    agent_seed: &str,
    user_did: &str,
    user_key_name: &str,
    user_name: &str,
    user_seed: &str,
    delegation_name: &str,
) -> Result<(), IdentityLibError> {
    let result = unsafe {
        let resolver_address = CStringRaw::new(resolver_address)?;
        let agent_did = CStringRaw::new(agent_did)?;
        let agent_key_name = CStringRaw::new(agent_key_name)?;
        let agent_name = CStringRaw::new(agent_name)?;
        let agent_seed = CStringRaw::new(agent_seed)?;
        let user_did = CStringRaw::new(user_did)?;
        let user_key_name = CStringRaw::new(user_key_name)?;
        let user_name = CStringRaw::new(user_name)?;
        let user_seed = CStringRaw::new(user_seed)?;
        let delegation_name = CStringRaw::new(delegation_name)?;

        ffi_wrapper::UserDelegatesAuthenticationToAgent(
            resolver_address.as_raw()?,
            agent_did.as_raw()?,
            agent_key_name.as_raw()?,
            agent_name.as_raw()?,
            agent_seed.as_raw()?,
            user_did.as_raw()?,
            user_key_name.as_raw()?,
            user_name.as_raw()?,
            user_seed.as_raw()?,
            delegation_name.as_raw()?,
        )
    };

    if !result.is_null() {
        let error = unsafe { CStr::from_ptr(result) }.to_str()?;
        let error = error.to_string();

        unsafe {
            ffi_wrapper::FreeUpCString(result);
        }

        return Err(IdentityLibError::Message(error));
    }

    Ok(())
}

/// Gets an authentication token used for connecting with the IOTICSpace.
///
/// Params:
/// - [`config`][Config] - Struct containing all the required secrets and parameters for working with this library.
///
/// Returns:
/// - [`Result`][Result::Ok] with [`String`] if generating a token success.
/// - [`Result`][Result::Err] with [`IdentityLibError`] if generating a token fails.
pub fn create_agent_auth_token(config: &Config) -> Result<String, IdentityLibError> {
    let result = unsafe {
        let agent_did = CStringRaw::new(config.agent_did.as_str())?;
        let agent_key_name = CStringRaw::new(config.agent_key_name.as_str())?;
        let agent_name = CStringRaw::new(config.agent_name.as_str())?;
        let agent_secret = CStringRaw::new(config.agent_secret.as_str())?;
        let user_did = CStringRaw::new(config.user_did.as_str())?;
        let resolver_address = CStringRaw::new(config.resolver_address.as_str())?;

        ffi_wrapper::CreateAgentAuthToken(
            agent_did.as_raw()?,
            agent_key_name.as_raw()?,
            agent_name.as_raw()?,
            agent_secret.as_raw()?,
            user_did.as_raw()?,
            // using resolver_address as audience
            resolver_address.as_raw()?,
            config.token_duration,
        )
    };

    match result.r1.is_null() {
        true => {
            let token = unsafe { CStr::from_ptr(result.r0) }.to_str()?;
            Ok(token.to_string())
        }
        false => {
            let error = unsafe { CStr::from_ptr(result.r1) }.to_str()?;
            Err(IdentityLibError::Message(error.to_string()))
        }
    }
}

/// Gets a twin DID that can be used for creating a real twin in the IOTICSpace.
///
/// Params:
/// - [`config`][Config] - Struct containing all the required secrets and parameters for working with this library.
/// - [`twin_key_name`][`str`] - Used to create a new (or regenerate already existing one) DID.
/// - [`twin_name`][`str`] - Will show up in the public document. Not used as part of the DID hash.
///
/// Returns:
/// - [`Result`][Result::Ok] with [`String`] if generating a DID succeeds.
/// - [`Result`][Result::Err] with [`IdentityLibError`] if generating a DID fails.
pub fn create_twin_did_with_control_delegation(
    config: &Config,
    twin_key_name: &str,
    twin_name: &str,
) -> Result<String, IdentityLibError> {
    let result = unsafe {
        let resolver_address = CStringRaw::new(config.resolver_address.as_str())?;
        let agent_did = CStringRaw::new(config.agent_did.as_str())?;
        let agent_key_name = CStringRaw::new(config.agent_key_name.as_str())?;
        let agent_name = CStringRaw::new(config.agent_name.as_str())?;
        let agent_secret = CStringRaw::new(config.agent_secret.as_str())?;
        let twin_key_name = CStringRaw::new(twin_key_name)?;
        let twin_name = CStringRaw::new(twin_name)?;

        ffi_wrapper::CreateTwinDidWithControlDelegation(
            resolver_address.as_raw()?,
            agent_did.as_raw()?,
            agent_key_name.as_raw()?,
            agent_name.as_raw()?,
            agent_secret.as_raw()?,
            twin_key_name.as_raw()?,
            twin_name.as_raw()?,
        )
    };

    match result.r1.is_null() {
        true => {
            let token = unsafe { CStr::from_ptr(result.r0) }.to_str()?;
            Ok(token.to_string())
        }
        false => {
            let error = unsafe { CStr::from_ptr(result.r1) }.to_str()?;
            Err(IdentityLibError::Message(error.to_string()))
        }
    }
}

struct CStringRaw {
    raw: Option<*mut libc::c_char>,
}

impl CStringRaw {
    pub fn new(value: &str) -> Result<Self, IdentityLibError> {
        let raw = CString::new(value)?.into_raw();

        Ok(Self { raw: Some(raw) })
    }

    pub fn as_raw(&self) -> Result<*mut libc::c_char, IdentityLibError> {
        self.raw
            .ok_or_else(|| IdentityLibError::Message("raw string pointer not present".to_string()))
    }
}

impl Drop for CStringRaw {
    fn drop(&mut self) {
        if let Some(raw) = self.raw.take() {
            unsafe { CString::from_raw(raw) };
        }
    }
}

impl Drop for ffi_wrapper::CreateUserIdentity_return {
    fn drop(&mut self) {
        unsafe {
            if !self.r0.is_null() {
                ffi_wrapper::FreeUpCString(self.r0);
            }
            if !self.r1.is_null() {
                ffi_wrapper::FreeUpCString(self.r1);
            }
        }
    }
}

impl Drop for ffi_wrapper::CreateAgentIdentity_return {
    fn drop(&mut self) {
        unsafe {
            if !self.r0.is_null() {
                ffi_wrapper::FreeUpCString(self.r0);
            }
            if !self.r1.is_null() {
                ffi_wrapper::FreeUpCString(self.r1);
            }
        }
    }
}

impl Drop for ffi_wrapper::CreateAgentAuthToken_return {
    fn drop(&mut self) {
        unsafe {
            if !self.r0.is_null() {
                ffi_wrapper::FreeUpCString(self.r0);
            }
            if !self.r1.is_null() {
                ffi_wrapper::FreeUpCString(self.r1);
            }
        }
    }
}

impl Drop for ffi_wrapper::CreateTwinDidWithControlDelegation_return {
    fn drop(&mut self) {
        unsafe {
            if !self.r0.is_null() {
                ffi_wrapper::FreeUpCString(self.r0);
            }
            if !self.r1.is_null() {
                ffi_wrapper::FreeUpCString(self.r1);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn it_works() {
        let resolver_address = "https://did.stg.iotics.com";

        let user_key_name = "00";
        let user_name = "#user-0";
        let user_seed = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

        let agent_key_name = "00";
        let agent_name = "#agent-0";
        let agent_seed = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

        let delegation_name = "#delegation-0";

        let user_did = create_user_identity(resolver_address, user_key_name, user_name, user_seed)
            .expect("Creating user identity failed.");

        let agent_did =
            create_agent_identity(resolver_address, agent_key_name, agent_name, agent_seed)
                .expect("Creating agent identity failed.");

        user_delegates_authentication_to_agent(
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

        let config = Config {
            resolver_address: resolver_address.to_string(),
            user_did: user_did.to_string(),
            agent_did: agent_did.to_string(),
            agent_key_name: agent_key_name.to_string(),
            agent_name: agent_name.to_string(),
            agent_secret: agent_seed.to_string(),
            token_duration: 600,
        };

        let _ = create_agent_auth_token(&config).expect("Creating token failed.");

        let twin_key_name = "00";
        let twin_name = "#twin-0";
        let _ = create_twin_did_with_control_delegation(&config, twin_key_name, twin_name)
            .expect("Creating twin DID failed.");
    }
}
