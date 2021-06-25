// Copyright (c) IOTIC LABS LIMITED. All rights reserved. Licensed under the Apache License, Version 2.0.

package register

import (
	"fmt"

	"github.com/Iotic-Labs/iotics-identity-go/pkg/proof"
	"github.com/Iotic-Labs/iotics-identity-go/pkg/validation"
)

// NewRegisterDelegationProof returns a new register delegation proof from the current setting revoke field.
func NewRegisterDelegationProof(name string, controller string, proof string, revoked bool) (*RegisterDelegationProof, error) {
	// NOTE: Python method was called build
	if err := validation.ValidateKeyName(name); err != nil {
		return nil, err
	}
	result := &RegisterDelegationProof{
		ID:         name,
		Controller: controller,
		Proof:      proof,
		Revoked:    revoked,
	}
	return result, nil
}

// Clone clone a RegisterDelegationProof
func (r RegisterDelegationProof) Clone() (*RegisterDelegationProof, error) {
	// NOTE: Python method was called get_new_key
	// NOTE: ignore error, because we're cloning a valid object
	return NewRegisterDelegationProof(r.ID, r.Controller, r.Proof, r.Revoked)
}

// ValidateDelegation Validate register delegation proof against the deleagtion controller register document.
func ValidateDelegation(resolverClient ResolverClient, registeredID string, registeredProof *RegisterDelegationProof) error {
	controllerIssuer, err := NewIssuerFromString(registeredProof.Controller)
	if err != nil {
		return err
	}

	controllerDoc, err := resolverClient.GetDocument(controllerIssuer.Did)
	if err != nil {
		return err
	}

	checkProof := &proof.Proof{
		IssuerDid:  controllerIssuer.Did,
		IssuerName: controllerIssuer.Name,
		Content:    []byte(registeredID),
		Signature:  registeredProof.Proof,
	}

	var controllerPublicKey *RegisterPublicKey
	for _, v := range controllerDoc.PublicKeys {
		if v.ID == controllerIssuer.Name {
			controllerPublicKey = &v
		}
	}
	if controllerPublicKey == nil {
		return fmt.Errorf("controller public key %s not found", controllerIssuer.Name)
	}

	return proof.ValidateProof(checkProof, controllerPublicKey.PublicKeyBase58)
}

func convertRegisterDelegationProofMapToSlice(keys map[string]*RegisterDelegationProof) []RegisterDelegationProof {
	authKeys := make([]RegisterDelegationProof, 0, len(keys))
	for _, v := range keys {
		authKeys = append(authKeys, RegisterDelegationProof{
			ID:         v.ID,
			Controller: v.Controller,
			Proof:      v.Proof,
			Revoked:    v.Revoked,
		})
	}
	return authKeys
}
