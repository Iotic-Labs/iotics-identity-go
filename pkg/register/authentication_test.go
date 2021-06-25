// Copyright (c) IOTIC LABS LIMITED. All rights reserved. Licensed under the Apache License, Version 2.0.

package register_test

import (
	"testing"
	"time"

	"github.com/Iotic-Labs/iotics-identity-go/pkg/advancedapi"
	"github.com/Iotic-Labs/iotics-identity-go/pkg/test"

	"github.com/Iotic-Labs/iotics-identity-go/pkg/register"
	"gotest.tools/assert"
)

func Test_validate_allowed_for_control_raises_not_allowed_if_not_allowed_for_control(t *testing.T) {
	resolver := test.NewInMemoryResolverEmpty()
	userIdentity, agentIdentity := test.SetupIdentitiesForAuth(resolver, false, true)

	err := register.ValidateAllowedForControl(resolver, agentIdentity.Issuer(), userIdentity.Did())
	assert.ErrorContains(t, err, "not allowed")
}

func Test_validate_allowed_for_control_raises_not_allowed_if_not_allowed_for_auth(t *testing.T) {
	resolver := test.NewInMemoryResolverEmpty()
	userIdentity, agentIdentity := test.SetupIdentitiesForAuth(resolver, false, false)

	err := register.ValidateAllowedForAuth(resolver, agentIdentity.Issuer(), userIdentity.Did())
	assert.ErrorContains(t, err, "not allowed")
}

func Test_can_validate_allowed_for_control_on_owned_doc(t *testing.T) {
	resolver := test.NewInMemoryResolverEmpty()
	userIdentity, _ := test.SetupIdentitiesForAuth(resolver, false, false)

	err := register.ValidateAllowedForControl(resolver, userIdentity.Issuer(), userIdentity.Did())
	assert.NilError(t, err)
}

func Test_can_validate_allowed_for_authentication_on_owned_doc(t *testing.T) {
	resolver := test.NewInMemoryResolverEmpty()
	userIdentity, _ := test.SetupIdentitiesForAuth(resolver, false, false)

	err := register.ValidateAllowedForAuth(resolver, userIdentity.Issuer(), userIdentity.Did())
	assert.NilError(t, err)
}

func Test_can_validate_allowed_for_control_with_allowed_by_control_delegation(t *testing.T) {
	resolver := test.NewInMemoryResolverEmpty()
	userIdentity, agentIdentity := test.SetupIdentitiesForAuth(resolver, true, false)

	err := register.ValidateAllowedForControl(resolver, agentIdentity.Issuer(), userIdentity.Did())
	assert.NilError(t, err)
}

func Test_can_validate_allowed_for_control_with_allowed_by_auth_delegation(t *testing.T) {
	resolver := test.NewInMemoryResolverEmpty()
	userIdentity, agentIdentity := test.SetupIdentitiesForAuth(resolver, false, true)

	err := register.ValidateAllowedForAuth(resolver, agentIdentity.Issuer(), userIdentity.Did())
	assert.NilError(t, err)
}

func Test_can_validate_allowed_for_control_with_controller_doc(t *testing.T) {
	resolver := test.NewInMemoryResolverEmpty()
	userIdentity, agentIdentity := test.SetupIdentitiesForAuth(resolver, false, false)

	advancedapi.SetDocumentController(resolver, userIdentity, agentIdentity.Issuer())

	err := register.ValidateAllowedForControl(resolver, agentIdentity.Issuer(), userIdentity.Did())
	assert.NilError(t, err)
}

func Test_can_validate_allowed_for_auth_with_controller_doc(t *testing.T) {
	resolver := test.NewInMemoryResolverEmpty()
	userIdentity, agentIdentity := test.SetupIdentitiesForAuth(resolver, false, false)

	advancedapi.SetDocumentController(resolver, userIdentity, agentIdentity.Issuer())

	err := register.ValidateAllowedForAuth(resolver, agentIdentity.Issuer(), userIdentity.Did())
	assert.NilError(t, err)
}

func Test_validate_allowed_for_control_raises_not_allowed_if_resolver_error(t *testing.T) {
	resolver := test.NewInMemoryResolverEmpty()
	_, agentIdentity := test.SetupIdentitiesForAuth(resolver, false, false)

	err := register.ValidateAllowedForAuth(resolver, agentIdentity.Issuer(), test.ValidDid)
	assert.ErrorContains(t, err, "document not found")
}

func Test_validate_allowed_for_auth_raises_not_allowed_if_resolver_error(t *testing.T) {

}

func Test_can_verify_authentication(t *testing.T) {
	resolver := test.NewInMemoryResolverEmpty()
	userIdentity, agentIdentity := test.SetupIdentitiesForAuth(resolver, true, false)

	duration, _ := time.ParseDuration("300s")
	token, err := register.CreateAuthToken(agentIdentity.Issuer(), userIdentity.Did(), "audience", duration, agentIdentity.KeyPair().PrivateKey, 0)
	assert.NilError(t, err)

	claims, err := register.VerifyAuthentication(resolver, token)
	assert.NilError(t, err)
	assert.DeepEqual(t, claims.Issuer, agentIdentity.Issuer())
	assert.Check(t, claims.Audience == "audience")
	assert.Check(t, claims.Subject == userIdentity.Did())
	assert.Check(t, claims.ExpiresAt-claims.IssuedAt == 300)
}

func Test_verify_authentication_raises_auth_error_if_invalid_token(t *testing.T) {
	resolver := test.NewInMemoryResolverEmpty()
	_, err := register.VerifyAuthentication(resolver, "invalid token")
	assert.ErrorContains(t, err, "failed to parse token")
}

func Test_verify_authentication_raises_auth_error_if_token_with_missing_data(t *testing.T) {

}

func Test_verify_authentication_raises_auth_error_if_invalid_issuer(t *testing.T) {

}

func Test_verify_authentication_raises_auth_error_if_resolver_error(t *testing.T) {

}

func Test_verify_authentication_raises_auth_error_if_issuer_not_in_doc_keys_or_deleg(t *testing.T) {

}

func Test_verify_authentication_raises_auth_error_if_token_invalid_signature(t *testing.T) {

}

func Test_verify_authentication_raises_auth_error_if_token_not_allowed(t *testing.T) {
	resolver := test.NewInMemoryResolverEmpty()
	userIdentity, agentIdentity := test.SetupIdentitiesForAuth(resolver, false, false)

	duration, _ := time.ParseDuration("300s")
	token, err := register.CreateAuthToken(agentIdentity.Issuer(), userIdentity.Did(), "audience", duration, agentIdentity.KeyPair().PrivateKey, 0)
	assert.NilError(t, err)

	_, err = register.VerifyAuthentication(resolver, token)
	assert.ErrorContains(t, err, "not allowed")
}
