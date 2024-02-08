// Copyright (c) IOTIC LABS LIMITED. All rights reserved. Licensed under the Apache License, Version 2.0.

package register

import (
	"context"
	"fmt"
)

// IsAllowFor Check if the issuer is allowed for control (authentication if include_auth = True) on the subject register.
// Returns both whether control is allowed as well as the associated error. (This can be used to e.g. treat certain errors
// differently such as ResolverError - or can instead be ignored).
func IsAllowFor(ctx context.Context, resolverClient ResolverClient, issuer *Issuer, issuerDoc *RegisterDocument, subjectDoc *RegisterDocument, includeAuth bool) (bool, error) {
	if issuerDoc.Revoked || subjectDoc.Revoked {
		return false, fmt.Errorf("issuer or subject document revoked")
	}

	if issuerDoc.ID == subjectDoc.ID { // Same document, if key exists and not revoked it is allowed
		issuerKey, _ := GetIssuerRegisterKey(issuer.Name, subjectDoc, includeAuth)
		if issuerKey != nil && !issuerKey.Revoked {
			return true, nil
		}
	}

	delegationProof, err := GetIssuerRegisterDelegationProofByController(issuer.String(), subjectDoc, includeAuth)
	if err != nil {
		return false, err
	}
	if !delegationProof.Revoked {
		err := ValidateDelegation(ctx, resolverClient, subjectDoc.ID, delegationProof)
		return err == nil, err
	}
	return false, fmt.Errorf("delegation proof revoked")
}

func checkAllowOnDocOrController(ctx context.Context, resolverClient ResolverClient, issuer *Issuer, subjectID string, includeAuth bool) error {
	issuerDoc, err := resolverClient.GetDocument(ctx, issuer.Did)
	if err != nil {
		return err
	}

	subjectDoc, err := resolverClient.GetDocument(ctx, subjectID)
	if err != nil {
		return err
	}

	if allowed, err := IsAllowFor(ctx, resolverClient, issuer, issuerDoc, subjectDoc, includeAuth); allowed {
		return nil
	} else if IsResolverError(err) || IsContextError(err) {
		// Don't continue if:
		// - failed to talk to resolver;
		// - context error (e.g. timeout).
		return err
	}

	if subjectDoc.Controller != "" {
		controllerDoc, err := resolverClient.GetDocument(ctx, subjectDoc.Controller)
		if err != nil {
			return err
		}

		if allowed, err := IsAllowFor(ctx, resolverClient, issuer, issuerDoc, controllerDoc, includeAuth); allowed {
			return nil
		} else if IsResolverError(err) || IsContextError(err) {
			return err
		}
	}

	return fmt.Errorf("not allowed")
}

// ValidateAllowedForControl Validate if issuer is allowed for control on the register document associated to the subject decentralised.
func ValidateAllowedForControl(ctx context.Context, resolverClient ResolverClient, issuer *Issuer, subjectID string) error {
	return checkAllowOnDocOrController(ctx, resolverClient, issuer, subjectID, false)
}

// ValidateAllowedForAuth Validate if issuer is allowed for authentication on the register document associated to the subject.
func ValidateAllowedForAuth(ctx context.Context, resolverClient ResolverClient, issuer *Issuer, subjectID string) error {
	return checkAllowOnDocOrController(ctx, resolverClient, issuer, subjectID, true)
}

// VerifyAuthentication Verify if the authentication token is allowed for authentication.
func VerifyAuthentication(ctx context.Context, resolverClient ResolverClient, token JwtToken) (*AuthenticationClaims, error) {
	unverifiedToken, err := DecodeAuthTokenNoVerify(token)
	if err != nil {
		return nil, err
	}

	issuerDoc, err := resolverClient.GetDocument(ctx, unverifiedToken.Issuer.Did)
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

	subjectDoc, err := resolverClient.GetDocument(ctx, unverifiedToken.Subject)
	if err != nil {
		return nil, err
	}

	if allowed, err := IsAllowFor(ctx, resolverClient, verifiedToken.Issuer, issuerDoc, subjectDoc, true); !allowed {
		return nil, err
	}

	return verifiedToken, nil
}
