// Copyright (c) IOTIC LABS LIMITED. All rights reserved. Licensed under the Apache License, Version 2.0.

package register

import (
	"context"
	"fmt"

	"github.com/Iotic-Labs/iotics-identity-go/v2/pkg/proof"
	"github.com/Iotic-Labs/iotics-identity-go/v2/pkg/validation"
)

// DelegationProofType
// 	- did:      that means the proof can be used to setup a delegation from single delegating subject.
//  			The signed proof content is the encoded DID Identifier of the delegating subject.
// 	- generic:  that means the proof can be used to setup a delegation from several delegating subjects.
//  			The signed proof content is an empty byte array.
// In case of conflict, unknown value, the most restrictive type (did) is used
type DelegationProofType string

const (
	DidProof     DelegationProofType = "did"
	GenericProof DelegationProofType = "generic"
)

// NewRegisterDelegationProof returns a new register delegation proof from the current setting revoke field.
func NewRegisterDelegationProof(name string, controller string, proof string, proofType DelegationProofType, revoked bool) (*RegisterDelegationProof, error) {
	// NOTE: Python method was called build
	if err := validation.ValidateKeyName(name); err != nil {
		return nil, err
	}
	result := &RegisterDelegationProof{
		ID:         name,
		Controller: controller,
		Proof:      proof,
		ProofType:  proofType,
		Revoked:    revoked,
	}
	return result, nil
}

// Clone clone a RegisterDelegationProof
func (r RegisterDelegationProof) Clone() (*RegisterDelegationProof, error) {
	// NOTE: Python method was called get_new_key
	// NOTE: ignore error, because we're cloning a valid object
	return NewRegisterDelegationProof(r.ID, r.Controller, r.Proof, r.ProofType, r.Revoked)
}

// ValidateDelegation Validate register delegation proof against the delegation controller register document.
func ValidateDelegation(ctx context.Context, resolverClient ResolverClient, registeredID string, registeredProof *RegisterDelegationProof) error {
	controllerIssuer, err := NewIssuerFromString(registeredProof.Controller)
	if err != nil {
		return err
	}

	controllerDoc, err := resolverClient.GetDocument(ctx, controllerIssuer.Did)
	if err != nil {
		return err
	}

	var controllerPublicKey *RegisterPublicKey
	for _, v := range controllerDoc.PublicKeys {
		if v.ID == controllerIssuer.Name {
			controllerPublicKey = &v // nolint:gosec
			break
		}
	}
	if controllerPublicKey == nil {
		return fmt.Errorf("controller public key %s not found", controllerIssuer.Name)
	}
	switch registeredProof.ProofType {
	case GenericProof:
		return checkProof(controllerIssuer, []byte(""), registeredProof.Proof, controllerPublicKey.PublicKeyBase58)
	case DidProof, "": // backward compatibility, default to the most restrictive mode (did)
		return checkProof(controllerIssuer, []byte(registeredID), registeredProof.Proof, controllerPublicKey.PublicKeyBase58)
	}

	return fmt.Errorf("invalid proof type: %s", registeredProof.ProofType)
}

func checkProof(issuer *Issuer, content []byte, signature string, publicKey string) error {

	checkProof := &proof.Proof{
		IssuerDid:  issuer.Did,
		IssuerName: issuer.Name,
		Content:    content,
		Signature:  signature,
	}
	return proof.ValidateProof(checkProof, publicKey)
}

func convertRegisterDelegationProofMapToSlice(keys map[string]*RegisterDelegationProof) []RegisterDelegationProof {
	authKeys := make([]RegisterDelegationProof, 0, len(keys))
	for _, v := range keys {
		authKeys = append(authKeys, RegisterDelegationProof{
			ID:         v.ID,
			Controller: v.Controller,
			Proof:      v.Proof,
			ProofType:  v.ProofType,
			Revoked:    v.Revoked,
		})
	}
	return authKeys
}
