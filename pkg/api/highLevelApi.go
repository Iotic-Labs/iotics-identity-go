// Copyright (c) IOTIC LABS LIMITED. All rights reserved. Licensed under the Apache License, Version 2.0.

package api

import (
	"time"

	"github.com/Iotic-Labs/iotics-identity-go/pkg/advancedapi"
	"github.com/Iotic-Labs/iotics-identity-go/pkg/crypto"
	"github.com/Iotic-Labs/iotics-identity-go/pkg/identity"
	"github.com/Iotic-Labs/iotics-identity-go/pkg/register"
)

const defaultSeedLength = 256

// CreateUserAndAgentWithAuthDelegation Create and register a user and an agent identities with user delegating authentication to the agent.
//func CreateUserAndAgentWithAuthDelegation(resolverClient register.ResolverClient, userSeed []byte, userKeyName string, agentSeed []byte, agentKeyName string, delegationName string, userName string, agentName string, userPassword string, agentPassword string, overrideDocs bool) (userID register.RegisteredIdentity, agentID register.RegisteredIdentity, err error) {
func CreateUserAndAgentWithAuthDelegation(resolverClient register.ResolverClient, opts *CreateUserAndAgentWithAuthDelegationOpts) (userID register.RegisteredIdentity, agentID register.RegisteredIdentity, err error) {
	userPath := crypto.PathForDIDType(opts.UserKeyName, identity.User)
	userSecrets, err := crypto.NewKeyPairSecrets(opts.UserSeed, userPath, crypto.SeedMethodBip39, opts.UserPassword)
	if err != nil {
		return nil, nil, err
	}
	userKeyPair, _ := crypto.GetKeyPair(userSecrets)
	userID, err = advancedapi.NewRegisteredIdentity(resolverClient, identity.User, userKeyPair, opts.UserName, opts.OverrideDocs)
	if err != nil {
		return userID, nil, err
	}

	agentPath := crypto.PathForDIDType(opts.AgentKeyName, identity.Agent)
	agentSecrets, err := crypto.NewDefaultKeyPairSecretsWithPassword(opts.AgentSeed, agentPath, opts.AgentPassword)
	agentKeyPair, _ := crypto.GetKeyPair(agentSecrets)
	if err != nil {
		return userID, nil, err
	}
	agentID, err = advancedapi.NewRegisteredIdentity(resolverClient, identity.Agent, agentKeyPair, opts.AgentName, opts.OverrideDocs)
	if err != nil {
		return userID, agentID, err
	}

	err = advancedapi.DelegateAuthentication(resolverClient, userKeyPair, userID.Did(), agentKeyPair, agentID.Did(), opts.DelegationName)
	if err != nil {
		return userID, agentID, err
	}

	return userID, agentID, nil
}

// CreateAgentAuthToken Create an agent authentication token.
func CreateAgentAuthToken(agentID register.RegisteredIdentity, userDid string, duration time.Duration, audience string) (register.JwtToken, error) {
	startOffset := register.DefaultAuthTokenStartOffset
	return advancedapi.CreateAgentAuthToken(agentID, userDid, duration, audience, startOffset)
}

// CreateTwinWithControlDelegation Create a twin with control delegation to Agent.
func CreateTwinWithControlDelegation(resolverClient register.ResolverClient, opts *CreateTwinOpts) (register.RegisteredIdentity, error) {
	createOpts := &CreateIdentityOpts{
		Seed:     opts.Seed,
		KeyName:  opts.KeyName,
		Password: opts.Password,
		Name:     opts.Name,
		Override: opts.OverideDoc,
	}
	twinID, err := CreateTwinIdentity(resolverClient, createOpts)
	if err != nil {
		return nil, err
	}
	err = DelegateControl(resolverClient, twinID, opts.AgentId, opts.DelegationName)
	return twinID, err
}

// DelegateControl registers a twin identity with twin delegating control to the agent
// NOTE: this is a duplicate of regularApi - TwinDelegatesControlToAgent
func DelegateControl(resolverClient register.ResolverClient, twinID register.RegisteredIdentity, agentID register.RegisteredIdentity, delegationName string) error {
	return advancedapi.DelegateControl(resolverClient, twinID.KeyPair(), twinID.Did(), agentID.KeyPair(), agentID.Did(), delegationName)
}

// GetOwnershipOfTwinFromRegisteredIdentity Get Ownership of a twin using a registered identity you owned.
func GetOwnershipOfTwinFromRegisteredIdentity(resolverClient register.ResolverClient, twinID register.RegisteredIdentity, newOwnerID register.RegisteredIdentity, newOwnerKeyName string) error {
	return advancedapi.AddPublicKeyToDocument(resolverClient, newOwnerKeyName, newOwnerID.KeyPair().PublicKeyBase58, twinID)
}

// CreateDefaultSeed Create a new seed (secrets) with the default length.
func CreateDefaultSeed() ([]byte, error) {
	return CreateSeed(defaultSeedLength)
}

// CreateSeed Create a new seed (secrets).
func CreateSeed(length int) ([]byte, error) {
	return advancedapi.CreateSeed(length)
}
