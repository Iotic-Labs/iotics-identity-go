// Copyright (c) IOTIC LABS LIMITED. All rights reserved. Licensed under the Apache License, Version 2.0.

package register

import (
	"fmt"
)

// IsAllowFor Check if the issuer is allowed for control (authentication if include_auth = True) on the subject register.
func IsAllowFor(resolverClient ResolverClient, issuer *Issuer, issuerDoc *RegisterDocument, subjectDoc *RegisterDocument, includeAuth bool) bool {
	if issuerDoc.Revoked || subjectDoc.Revoked {
		return false
	}

	if issuerDoc.ID == subjectDoc.ID { // Same document, if key exists and not revoked it is allowed
		issuerKey, _ := GetIssuerRegisterKey(issuer.Name, subjectDoc, includeAuth)
		if issuerKey != nil && !issuerKey.Revoked {
			return true
		}
	}

	delegationProof, _ := GetIssuerRegisterDelegationProofByController(issuer.String(), subjectDoc, includeAuth)
	if delegationProof != nil && delegationProof.Revoked == false {
		return nil == ValidateDelegation(resolverClient, subjectDoc.ID, delegationProof)
	}

	return false
}

func checkAllowOnDocOrController(resolverClient ResolverClient, issuer *Issuer, subjectID string, includeAuth bool) error {
	issuerDoc, err := resolverClient.GetDocument(issuer.Did)
	if err != nil {
		return err
	}

	subjectDoc, err := resolverClient.GetDocument(subjectID)
	if err != nil {
		return err
	}

	if IsAllowFor(resolverClient, issuer, issuerDoc, subjectDoc, includeAuth) {
		return nil
	}

	if subjectDoc.Controller != "" {
		controllerDoc, err := resolverClient.GetDocument(subjectDoc.Controller)
		if err != nil {
			return err
		}

		if IsAllowFor(resolverClient, issuer, issuerDoc, controllerDoc, includeAuth) {
			return nil
		}
	}

	return fmt.Errorf("not allowed")
}

// ValidateAllowedForControl Validate if issuer is allowed for control on the register document associated to the subject decentralised.
func ValidateAllowedForControl(resolverClient ResolverClient, issuer *Issuer, subjectID string) error {
	return checkAllowOnDocOrController(resolverClient, issuer, subjectID, false)
}

// ValidateAllowedForAuth Validate if issuer is allowed for authentication on the register document associated to the subject.
func ValidateAllowedForAuth(resolverClient ResolverClient, issuer *Issuer, subjectID string) error {
	return checkAllowOnDocOrController(resolverClient, issuer, subjectID, true)
}

// VerifyAuthentication Verify if the authentication token is allowed for authentication.
func VerifyAuthentication(resolverClient ResolverClient, token JwtToken) (*AuthenticationClaims, error) {
	unverifiedToken, err := DecodeAuthTokenNoVerify(token)
	if err != nil {
		return nil, err
	}

	issuerDoc, err := resolverClient.GetDocument(unverifiedToken.Issuer.Did)
	if err != nil {
		return nil, err
	}

	issuerKey, err := GetIssuerRegisterKey(unverifiedToken.Issuer.Name, issuerDoc, true)
	if err != nil {
		return nil, err
	}

	verifiedToken, err := DecodeAuthToken(token, issuerKey.PublicKeyBase58, unverifiedToken.Audience)
	if err != nil {
		return nil, err
	}

	subjectDoc, err := resolverClient.GetDocument(unverifiedToken.Subject)
	if err != nil {
		return nil, err
	}

	if !IsAllowFor(resolverClient, verifiedToken.Issuer, issuerDoc, subjectDoc, true) {
		return nil, fmt.Errorf("not allowed")
	}

	return verifiedToken, nil
}
