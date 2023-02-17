// Copyright (c) IOTIC LABS LIMITED. All rights reserved. Licensed under the Apache License, Version 2.0.

package api

import (
	"context"

	"github.com/Iotic-Labs/iotics-identity-go/v2/pkg/advancedapi"
	"github.com/Iotic-Labs/iotics-identity-go/v2/pkg/crypto"
	"github.com/Iotic-Labs/iotics-identity-go/v2/pkg/identity"
	"github.com/Iotic-Labs/iotics-identity-go/v2/pkg/register"
)

func createIdentity(
	ctx context.Context, resolverClient register.ResolverClient, purpose identity.DidType, opts *CreateIdentityOpts,
) (register.RegisteredIdentity, error) {
	path := crypto.PathForDIDType(opts.KeyName, purpose)
	secrets, err := crypto.NewKeyPairSecrets(opts.Seed, path, opts.Method, opts.Password)
	if err != nil {
		return nil, err
	}
	keyPair, err := crypto.GetKeyPair(secrets)
	if err != nil {
		return nil, err
	}

	createdIdentity, _, err := advancedapi.CreateNewIdentityAndRegister(
		ctx, resolverClient, purpose, keyPair, opts.Name, opts.Override,
	)
	return createdIdentity, err
}

// CreateUserIdentity Create and register a user identity.
func CreateUserIdentity(
	ctx context.Context, resolverClient register.ResolverClient, opts *CreateIdentityOpts,
) (register.RegisteredIdentity, error) {
	return createIdentity(ctx, resolverClient, identity.User, opts)
}

// CreateAgentIdentity Create and register a agent identity.
func CreateAgentIdentity(
	ctx context.Context, resolverClient register.ResolverClient, opts *CreateIdentityOpts,
) (register.RegisteredIdentity, error) {
	return createIdentity(ctx, resolverClient, identity.Agent, opts)
}

// CreateTwinIdentity Create and register a twin identity.
func CreateTwinIdentity(
	ctx context.Context, resolverClient register.ResolverClient, opts *CreateIdentityOpts,
) (register.RegisteredIdentity, error) {
	return createIdentity(ctx, resolverClient, identity.Twin, opts)
}

func getIdentity(purpose identity.DidType, opts *GetIdentityOpts) (register.RegisteredIdentity, error) {
	path := crypto.PathForDIDType(opts.KeyName, purpose)
	keyPairSecrets, err := crypto.NewKeyPairSecrets(opts.Seed, path, opts.Method, opts.Password)
	if err != nil {
		return nil, err
	}
	keyPair, _ := crypto.GetKeyPair(keyPairSecrets)
	issuer, err := register.NewIssuer(opts.Did, opts.Name)
	if err != nil {
		return nil, err
	}

	return register.NewRegisteredIdentity(keyPair, issuer), nil
}

// GetUserIdentity Get user registered identity from secrets.
func GetUserIdentity(opts *GetIdentityOpts) (register.RegisteredIdentity, error) {
	return getIdentity(identity.User, opts)
}

// GetAgentIdentity Get agent registered identity from secrets.
func GetAgentIdentity(opts *GetIdentityOpts) (register.RegisteredIdentity, error) {
	return getIdentity(identity.Agent, opts)
}

// GetTwinIdentity Get twin registered identity from secrets.
func GetTwinIdentity(opts *GetIdentityOpts) (register.RegisteredIdentity, error) {
	return getIdentity(identity.Twin, opts)
}

// UserDelegatesAuthenticationToAgent User delegates authentication to agent.
func UserDelegatesAuthenticationToAgent(
	ctx context.Context, resolverClient register.ResolverClient, userIdentity register.RegisteredIdentity,
	agentIdentity register.RegisteredIdentity, delegationName string,
) error {
	opts := advancedapi.DelegationOpts{
		ResolverClient:    resolverClient,
		DelegatingKeyPair: userIdentity.KeyPair(),
		DelegatingDid:     userIdentity.Did(),
		SubjectKeyPair:    agentIdentity.KeyPair(),
		SubjectDid:        agentIdentity.Did(),
		Name:              delegationName,
	}
	return advancedapi.DelegateAuthentication(ctx, opts)
}

// TwinDelegatesControlToAgent Twin delegates control to the agent. The agent can control the twin.
func TwinDelegatesControlToAgent(
	ctx context.Context, resolverClient register.ResolverClient, twinIdentity register.RegisteredIdentity,
	agentIdentity register.RegisteredIdentity, delegationName string,
) error {
	opts := advancedapi.DelegationOpts{
		ResolverClient:    resolverClient,
		DelegatingKeyPair: twinIdentity.KeyPair(),
		DelegatingDid:     twinIdentity.Did(),
		SubjectKeyPair:    agentIdentity.KeyPair(),
		SubjectDid:        agentIdentity.Did(),
		Name:              delegationName,
	}
	return advancedapi.DelegateControl(ctx, opts)
}

// SetDocumentController Set controller issuer to the register document associated to the provided registered identity.
func SetDocumentController(
	ctx context.Context, resolverClient register.ResolverClient, identity register.RegisteredIdentity,
	controller *register.Issuer,
) error {
	return advancedapi.SetDocumentController(ctx, resolverClient, nil, identity, controller)
}

// SetDocumentCreator Set creator to the register document associated to the provided registered identity.
func SetDocumentCreator(
	ctx context.Context, resolverClient register.ResolverClient, identity register.RegisteredIdentity,
	creator *register.Issuer,
) error {
	return advancedapi.SetDocumentCreator(ctx, resolverClient, nil, identity, creator)
}

// SetDocumentRevoked Set register document associated to the provided registered identity revoke field.
func SetDocumentRevoked(
	ctx context.Context, resolverClient register.ResolverClient, identity register.RegisteredIdentity,
	revoked bool,
) error {
	return advancedapi.SetDocumentRevoked(ctx, resolverClient, nil, identity, revoked)
}

// GetRegisteredDocument Get a register document from the resolver.
func GetRegisteredDocument(
	ctx context.Context, resolverClient register.ResolverClient, did string,
) (*register.RegisterDocument, error) {
	return advancedapi.GetRegisterDocument(ctx, resolverClient, did)
}

// ValidateDocumentProof Verify a register document proof.
func ValidateDocumentProof(doc *register.RegisterDocument) error {
	return advancedapi.ValidateDocumentProof(doc)
}

func getKeyPair(purpose identity.DidType, opts *GetKeyPairOpts) (*crypto.KeyPair, error) {
	path := crypto.PathForDIDType(opts.KeyName, purpose)
	keyPairSecrets, err := crypto.NewKeyPairSecrets(opts.Seed, path, opts.Method, opts.Password)
	if err != nil {
		return nil, err
	}
	return crypto.GetKeyPair(keyPairSecrets)
}

// GetKeyPairFromUser Get key pair from user secrets.
func GetKeyPairFromUser(opts *GetKeyPairOpts) (*crypto.KeyPair, error) {
	return getKeyPair(identity.User, opts)
}

// GetKeyPairFromAgent Get key pair from agent secrets.
func GetKeyPairFromAgent(opts *GetKeyPairOpts) (*crypto.KeyPair, error) {
	return getKeyPair(identity.Agent, opts)
}

// GetKeyPairFromTwin Get key pair from twin secrets.
func GetKeyPairFromTwin(opts *GetKeyPairOpts) (*crypto.KeyPair, error) {
	return getKeyPair(identity.Twin, opts)
}

// AddNewOwner Add new register document owner.
func AddNewOwner(
	ctx context.Context, resolverClient register.ResolverClient, newOwnerName string, newOwnerPublicBase58 string,
	identity register.RegisteredIdentity,
) error {
	return advancedapi.AddPublicKeyToDocument(
		ctx, resolverClient, nil, newOwnerName, newOwnerPublicBase58, identity,
	)
}

// RemoveOwnership Remove owner from a register document.
func RemoveOwnership(
	ctx context.Context, resolverClient register.ResolverClient, removeOwnerName string, identity register.RegisteredIdentity,
) error {
	return advancedapi.RemovePublicKeyFromDocument(ctx, resolverClient, nil, removeOwnerName, identity)
}
