// Copyright (c) IOTIC LABS LIMITED. All rights reserved. Licensed under the Apache License, Version 2.0.

package register_test

import (
	"context"
	"testing"

	"gotest.tools/assert"

	"github.com/Iotic-Labs/iotics-identity-go/v2/pkg/proof"
	"github.com/Iotic-Labs/iotics-identity-go/v2/pkg/register"
	"github.com/Iotic-Labs/iotics-identity-go/v2/pkg/test"
)

func Test_validate_delegation_fails_if_invalid_controller_issuer(t *testing.T) {
	invalidRegisteredProof := &register.RegisterDelegationProof{
		Controller: "notAnIssuer",
	}
	err := register.ValidateDelegation(context.TODO(), nil, "registeredDid", invalidRegisteredProof)
	assert.ErrorContains(t, err, "invalid issuer string")
}

func Test_validate_delegation_fails_if_can_not_get_controller_doc(t *testing.T) {
	invalidRegisteredProof := &register.RegisterDelegationProof{
		Controller: "did:iotics:iotTdY27bo6ycsVs49T35QuPHZfjrJ3P41NR#user-name",
	}
	resolver := test.NewInMemoryResolver()
	err := register.ValidateDelegation(context.TODO(), resolver, "registeredDid", invalidRegisteredProof)
	assert.ErrorContains(t, err, "document not found")
}

func Test_validate_delegation_fails_controller_public_key_not_found(t *testing.T) {
	controllerDoc, _, _ := test.HelperGetRegisterDocument()
	registeredProof := &register.RegisterDelegationProof{
		Controller: "did:iotics:iotTdY27bo6ycsVs49T35QuPHZfjrJ3P41NR#different-issuer",
	}
	resolver := test.NewInMemoryResolver(controllerDoc)
	err := register.ValidateDelegation(context.TODO(), resolver, "registeredDid", registeredProof)
	assert.ErrorContains(t, err, "controller public key #different-issuer not found")
}

func Test_validate_delegation_fails_if_content_does_not_match_proof_type(t *testing.T) {
	type params struct {
		proofType register.DelegationProofType
		content   []byte
	}
	registeredDID := "did:aregisteredDID"
	for name, params := range map[string]params{
		"invalid did content":     {register.DidProof, []byte("")},
		"invalid generic content": {register.GenericProof, []byte(registeredDID)},
	} {
		t.Run(name, func(t *testing.T) {
			controllerDoc, issuer, keyPair := test.HelperGetRegisterDocument()
			cryptoProof, err := proof.NewProof(keyPair.PrivateKey, issuer.Did, issuer.Name, params.content)
			assert.NilError(t, err)
			registeredProof, err := register.NewRegisterDelegationProof("#ProofName", issuer.String(), cryptoProof.Signature, params.proofType, false)
			assert.NilError(t, err)
			resolver := test.NewInMemoryResolver(controllerDoc)
			err = register.ValidateDelegation(context.TODO(), resolver, registeredDID, registeredProof)
			assert.ErrorContains(t, err, "invalid signature")
		})
	}
}

func Test_validate_delegation_succeeds_for_did_proof_type(t *testing.T) {
	controllerDoc, issuer, keyPair := test.HelperGetRegisterDocument()
	registeredDID := "did:aregisteredDID"
	proofContent := []byte(registeredDID)

	cryptoProof, err := proof.NewProof(keyPair.PrivateKey, issuer.Did, issuer.Name, proofContent)
	assert.NilError(t, err)
	registeredProof, err := register.NewRegisterDelegationProof("#ProofName", issuer.String(), cryptoProof.Signature, register.DidProof, false)
	assert.NilError(t, err)
	resolver := test.NewInMemoryResolver(controllerDoc)
	err = register.ValidateDelegation(context.TODO(), resolver, registeredDID, registeredProof)
	assert.NilError(t, err)
}

func Test_validate_delegation_succeeds_for_generic_proof_type(t *testing.T) {
	controllerDoc, issuer, keyPair := test.HelperGetRegisterDocument()
	registeredDID := "did:aregisteredDID"
	proofContent := []byte("")

	cryptoProof, err := proof.NewProof(keyPair.PrivateKey, issuer.Did, issuer.Name, proofContent)
	assert.NilError(t, err)
	registeredProof, err := register.NewRegisterDelegationProof("#ProofName", issuer.String(), cryptoProof.Signature, register.GenericProof, false)
	assert.NilError(t, err)
	resolver := test.NewInMemoryResolver(controllerDoc)
	err = register.ValidateDelegation(context.TODO(), resolver, registeredDID, registeredProof)
	assert.NilError(t, err)
}

func Test_validate_delegation_succeeds_for_unset_proof_type_backward_compatibility(t *testing.T) {
	controllerDoc, issuer, keyPair := test.HelperGetRegisterDocument()
	registeredDID := "did:aregisteredDID"
	proofContent := []byte(registeredDID)
	cryptoProof, err := proof.NewProof(keyPair.PrivateKey, issuer.Did, issuer.Name, proofContent)
	assert.NilError(t, err)

	registeredProof, err := register.NewRegisterDelegationProof("#ProofName", issuer.String(), cryptoProof.Signature, register.GenericProof, false)
	assert.NilError(t, err)
	registeredProof.ProofType = ""
	resolver := test.NewInMemoryResolver(controllerDoc)
	err = register.ValidateDelegation(context.TODO(), resolver, registeredDID, registeredProof)
	assert.NilError(t, err)
}

func Test_validate_delegation_fails_if_unknown_proof_type(t *testing.T) {
	controllerDoc, issuer, keyPair := test.HelperGetRegisterDocument()
	registeredDID := "did:aregisteredDID"
	proofContent := []byte(registeredDID)
	cryptoProof, err := proof.NewProof(keyPair.PrivateKey, issuer.Did, issuer.Name, proofContent)
	assert.NilError(t, err)

	registeredProof, err := register.NewRegisterDelegationProof("#ProofName", issuer.String(), cryptoProof.Signature, register.GenericProof, false)
	assert.NilError(t, err)
	registeredProof.ProofType = "unknown"
	resolver := test.NewInMemoryResolver(controllerDoc)
	err = register.ValidateDelegation(context.TODO(), resolver, registeredDID, registeredProof)
	assert.ErrorContains(t, err, "invalid proof type: unknown")
}
