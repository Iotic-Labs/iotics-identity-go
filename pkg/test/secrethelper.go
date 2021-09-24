// Copyright (c) IOTIC LABS LIMITED. All rights reserved. Licensed under the Apache License, Version 2.0.

package test

import (
	"github.com/Iotic-Labs/iotics-identity-go/pkg/advancedapi"
	"github.com/Iotic-Labs/iotics-identity-go/pkg/crypto"
	"github.com/Iotic-Labs/iotics-identity-go/pkg/identity"
	"github.com/Iotic-Labs/iotics-identity-go/pkg/proof"
	"github.com/Iotic-Labs/iotics-identity-go/pkg/register"
)

func HelperGetRegisterDocumentFromSecret(keypair *crypto.KeyPair, name string, purpose identity.DidType) (*register.RegisterDocument, *register.Issuer) {
	identifier, _ := identity.MakeIdentifier(keypair.PublicKeyBytes)
	issuer, _ := register.NewIssuer(identifier, name)
	newProof, _ := proof.NewProof(keypair.PrivateKey, issuer.Did, issuer.Name, []byte(identifier))

	opts := []register.RegisterDocumentOpts{
		register.AddRootParams(identifier, purpose, newProof.Signature, false),
		register.AddPublicKey(name, keypair.PublicKeyBase58, false),
	}
	registerDocument, _ := register.NewRegisterDocument(opts)

	return registerDocument, issuer
}

func HelperGetRegisterDocument() (*register.RegisterDocument, *register.Issuer, *crypto.KeyPair) {
	identifier, _ := identity.MakeIdentifier(ValidKeyPair.PublicKeyBytes)
	name := "#user-name"
	name2 := "#name2"
	issuer, _ := register.NewIssuer(identifier, name)
	proof, _ := proof.NewProof(ValidPrivateKey, issuer.Did, issuer.Name, []byte(identifier))

	opts := []register.RegisterDocumentOpts{
		register.AddRootParams(identifier, identity.User, proof.Signature, false),
		register.AddPublicKey(name, ValidKeyPair.PublicKeyBase58, false),
		register.AddAuthenticationKey(name2, ValidKeyPair2.PublicKeyBase58, false),
	}
	registerDocument, _ := register.NewRegisterDocument(opts)

	return registerDocument, issuer, ValidKeyPair
}

func SetupIdentitiesForAuth(resolver register.ResolverClient, control bool, auth bool) (register.RegisteredIdentity, register.RegisteredIdentity) {
	userSecret, _ := crypto.NewDefaultKeyPairSecrets(ValidBip39Seed32B, "iotics/0/user/00")
	userKeypair, _ := crypto.GetKeyPair(userSecret)
	userIdentity, _ := advancedapi.NewRegisteredIdentity(resolver, identity.User, userKeypair, "#user", true)

	agentSecret, _ := crypto.NewDefaultKeyPairSecrets(ValidBip39Seed32B, "iotics/0/agent/00")
	agentKeypair, _ := crypto.GetKeyPair(agentSecret)
	agentIdentity, _ := advancedapi.NewRegisteredIdentity(resolver, identity.Agent, agentKeypair, "#agent", true)

	if control {
		opts.Name = "#delegCtrl"
		_ = advancedapi.DelegateControl(opts)
	} else if auth {
		opts.Name = "#delegAuth"
		_ = advancedapi.DelegateAuthentication(opts)
	}

	return userIdentity, agentIdentity
}
