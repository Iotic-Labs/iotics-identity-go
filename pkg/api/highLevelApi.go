// Copyright (c) IOTIC LABS LIMITED. All rights reserved. Licensed under the Apache License, Version 2.0.

package api

import (
	"fmt"
	"time"

	"github.com/Iotic-Labs/iotics-identity-go/pkg/advancedapi"
	"github.com/Iotic-Labs/iotics-identity-go/pkg/crypto"
	"github.com/Iotic-Labs/iotics-identity-go/pkg/identity"
	"github.com/Iotic-Labs/iotics-identity-go/pkg/register"
)

const (
	defaultSeedLength = 256
	defaultSeedMethod = crypto.SeedMethodBip39
)

// CreateUserAndAgentWithAuthDelegation Create and register a user and an agent identities with user delegating authentication to the agent.
//func CreateUserAndAgentWithAuthDelegation(resolverClient register.ResolverClient, userSeed []byte, userKeyName string, agentSeed []byte, agentKeyName string, delegationName string, userName string, agentName string, userPassword string, agentPassword string, overrideDocs bool) (userID register.RegisteredIdentity, agentID register.RegisteredIdentity, err error) {
func CreateUserAndAgentWithAuthDelegation(resolverClient register.ResolverClient, opts *CreateUserAndAgentWithAuthDelegationOpts) (userID register.RegisteredIdentity, agentID register.RegisteredIdentity, err error) {
	agentPath := crypto.PathForDIDType(opts.AgentKeyName, identity.Agent)
	agentSecrets, err := crypto.NewDefaultKeyPairSecretsWithPassword(opts.AgentSeed, agentPath, opts.AgentPassword)
	if err != nil {
		return nil, nil, err
	}
	agentKeyPair, err := crypto.GetKeyPair(agentSecrets)
	if err != nil {
		return nil, nil, err
	}

	agentID, agentDocument, err := advancedapi.CreateNewIdentityAndRegister(resolverClient, identity.Agent, agentKeyPair, opts.AgentName, false)
	if err != nil {
		return nil, nil, err
	}

	userPath := crypto.PathForDIDType(opts.UserKeyName, identity.User)
	userSecrets, err := crypto.NewKeyPairSecrets(opts.UserSeed, userPath, defaultSeedMethod, opts.UserPassword)
	if err != nil {
		return nil, nil, err
	}
	userKeyPair, err := crypto.GetKeyPair(userSecrets)
	if err != nil {
		return nil, nil, err
	}
	userDocument, userIssuer, err := advancedapi.CreateNewDocument(identity.User, userKeyPair, opts.UserName)
	if err != nil {
		return nil, nil, err
	}

	delegOpts := advancedapi.DelegationOpts{
		ResolverClient:     resolverClient,
		DelegatingKeyPair:  userKeyPair,
		DelegatingDid:      userIssuer.Did,
		DelegatingDocument: userDocument,
		SubjectKeyPair:     agentKeyPair,
		SubjectDid:         agentID.Did(),
		SubjectDocument:    agentDocument,
		Name:               opts.DelegationName,
	}
	err = advancedapi.DelegateAuthentication(delegOpts)
	if err != nil {
		return nil, nil, err
	}

	userID = register.NewRegisteredIdentity(userKeyPair, userIssuer)

	return userID, agentID, nil
}

// CreateAgentAuthToken Create an agent authentication token.
func CreateAgentAuthToken(agentID register.RegisteredIdentity, userDid string, duration time.Duration, audience string) (register.JwtToken, error) {
	startOffset := register.DefaultAuthTokenStartOffset
	return advancedapi.CreateAgentAuthToken(agentID, userDid, duration, audience, startOffset)
}

// CreateTwinWithControlDelegation Create a twin with control delegation to Agent.
func CreateTwinWithControlDelegation(resolverClient register.ResolverClient, opts *CreateTwinOpts) (register.RegisteredIdentity, error) {
	twinPath := crypto.PathForDIDType(opts.KeyName, identity.Twin)
	twinSecrets, err := crypto.NewKeyPairSecrets(opts.Seed, twinPath, defaultSeedMethod, opts.Password)
	if err != nil {
		return nil, err
	}
	twinKeyPair, err := crypto.GetKeyPair(twinSecrets)
	if err != nil {
		return nil, err
	}
	twinDocument, twinIssuer, err := advancedapi.CreateNewDocument(identity.Twin, twinKeyPair, opts.Name)
	if err != nil {
		return nil, err
	}

	delegOpts := advancedapi.DelegationOpts{
		ResolverClient:     resolverClient,
		DelegatingKeyPair:  twinKeyPair,
		DelegatingDid:      twinIssuer.Did,
		DelegatingDocument: twinDocument,
		SubjectKeyPair:     opts.AgentID.KeyPair(),
		SubjectDid:         opts.AgentID.Did(),
		SubjectDocument:    opts.AgentDoc,
		Name:               opts.DelegationName,
	}
	err = advancedapi.DelegateControl(delegOpts)
	if err != nil {
		return nil, err
	}

	twinIdentity := register.NewRegisteredIdentity(twinKeyPair, twinIssuer)

	return twinIdentity, nil
}

// DelegateControl registers a twin identity with twin delegating control to the agent
// NOTE: this is a duplicate of regularApi - TwinDelegatesControlToAgent
func DelegateControl(resolverClient register.ResolverClient, twinID register.RegisteredIdentity, agentID register.RegisteredIdentity, delegationName string) error {
	return TwinDelegatesControlToAgent(resolverClient, twinID, agentID, delegationName)
}

// GetOwnershipOfTwinFromRegisteredIdentity Get Ownership of a twin using a registered identity you owned.
func GetOwnershipOfTwinFromRegisteredIdentity(resolverClient register.ResolverClient, twinID register.RegisteredIdentity, newOwnerID register.RegisteredIdentity, newOwnerKeyName string) error {
	return advancedapi.AddPublicKeyToDocument(resolverClient, nil, newOwnerKeyName, newOwnerID.KeyPair().PublicKeyBase58, twinID)
}

// CreateDefaultSeed Create a new seed (secrets) with the default length.
func CreateDefaultSeed() ([]byte, error) {
	return CreateSeed(defaultSeedLength)
}

// CreateSeed Create a new seed (secrets).
func CreateSeed(length int) ([]byte, error) {
	return advancedapi.CreateSeed(length)
}

// DelegateControlByPrivateExponentHex registers a twin identity with a control delegate to agent
func DelegateControlByPrivateExponentHex(resolverClient register.ResolverClient, twinIssuer *register.Issuer, twinPrivateExponent string, agentID register.RegisteredIdentity, delegationName string) error {
	twinKeypair, err := advancedapi.GetKeyPairFromPrivateExponentHex(twinPrivateExponent)
	if err != nil {
		return err
	}

	twinID := register.NewRegisteredIdentity(twinKeypair, twinIssuer)

	return TwinDelegatesControlToAgent(resolverClient, twinID, agentID, delegationName)
}

// TakeOwnershipOfTwinByPrivateExponentHex Get Ownership of a twin using the private exponent of the twin.
func TakeOwnershipOfTwinByPrivateExponentHex(resolverClient register.ResolverClient, twinIssuer *register.Issuer, twinPrivateExponent string, newOwnerID register.RegisteredIdentity, newOwnerKeyName string) error {
	twinKeypair, err := advancedapi.GetKeyPairFromPrivateExponentHex(twinPrivateExponent)
	if err != nil {
		return err
	}

	twinID := register.NewRegisteredIdentity(twinKeypair, twinIssuer)

	return advancedapi.AddPublicKeyToDocument(resolverClient, nil, newOwnerKeyName, newOwnerID.KeyPair().PublicKeyBase58, twinID)
}

// TakeOwnershipOfTwinAndDelegateControlByPrivateExponentHex Get Ownership of a twin using the agent identity and delegate control to that agent using twin private key exponent.
func TakeOwnershipOfTwinAndDelegateControlByPrivateExponentHex(resolverClient register.ResolverClient, twinIssuer *register.Issuer, twinPrivateExponent string, newOwnerID register.RegisteredIdentity, newOwnerKeyName string, delegationName string) error {
	twinKeypair, err := advancedapi.GetKeyPairFromPrivateExponentHex(twinPrivateExponent)
	if err != nil {
		return err
	}

	twinDoc, err := resolverClient.GetDocument(twinIssuer.Did)
	if err != nil {
		return err
	}

	dProof, err := advancedapi.CreateProof(newOwnerID.KeyPair(), newOwnerID.Issuer(), []byte(twinIssuer.Did))
	if err != nil {
		return err
	}

	opts := []register.RegisterDocumentOpts{
		register.AddFromExistingDocument(twinDoc),
		register.AddPublicKey(newOwnerKeyName, newOwnerID.KeyPair().PublicKeyBase58, false),
		register.AddControlDelegation(delegationName, newOwnerID.Issuer().String(), dProof.Signature, false),
	}
	updatedDoc, errs := register.NewRegisterDocument(opts)
	if len(errs) != 0 {
		return fmt.Errorf("error while creating new RegisterDocument: %v", errs)
	}

	return advancedapi.RegisterUpdatedDocument(resolverClient, updatedDoc, twinKeypair, twinIssuer)
}
