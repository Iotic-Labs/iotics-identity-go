// Copyright (c) IOTIC LABS LIMITED. All rights reserved. Licensed under the Apache License, Version 2.0.

package register

import (
	"fmt"

	"github.com/Iotic-Labs/iotics-identity-go/pkg/identity"
	"github.com/jbenet/go-base58"
)

// GetOwnerRegisterPublicKey Get the register document initial owner public key.
func GetOwnerRegisterPublicKey(document *RegisterDocument) (*RegisterPublicKey, error) {
	for _, v := range document.PublicKeys {
		publicKeyBytes := base58.DecodeAlphabet(v.PublicKeyBase58, base58.BTCAlphabet)
		id, _ := identity.MakeIdentifier(publicKeyBytes)
		if id == document.ID {
			return &v, nil
		}
	}
	return nil, fmt.Errorf("owner key not found")
}

// GetIssuerRegisterKey Find a register key by issuer.
func GetIssuerRegisterKey(issuerName string, document *RegisterDocument, includeAuth bool) (*RegisterPublicKey, error) {
	for _, v := range document.PublicKeys {
		if v.ID == issuerName {
			return &v, nil
		}
	}
	if includeAuth {
		for _, v := range document.AuthenticationKeys {
			if v.ID == issuerName {
				return &v, nil
			}
		}
	}
	return nil, fmt.Errorf("issuer key not found")
}

// GetIssuerRegisterDelegationProof Find a register delegation proof by issuer.
func GetIssuerRegisterDelegationProof(issuerName string, document *RegisterDocument, includeAuth bool) (*RegisterDelegationProof, error) {
	for _, v := range document.DelegateControl {
		if v.ID == issuerName {
			return &v, nil
		}
	}
	if includeAuth {
		for _, v := range document.DelegateAuthentication {
			if v.ID == issuerName {
				return &v, nil
			}
		}
	}
	return nil, fmt.Errorf("delegation now found for issuer")
}

// GetIssuerRegisterDelegationProofByController Find a register delegation proof by controller issuer.
func GetIssuerRegisterDelegationProofByController(controller string, document *RegisterDocument, includeAuth bool) (*RegisterDelegationProof, error) {
	for _, v := range document.DelegateControl {
		if v.Controller == controller {
			return &v, nil
		}
	}
	if includeAuth {
		for _, v := range document.DelegateAuthentication {
			if v.Controller == controller {
				return &v, nil
			}
		}
	}
	return nil, fmt.Errorf("delegation not found for controller")
}
