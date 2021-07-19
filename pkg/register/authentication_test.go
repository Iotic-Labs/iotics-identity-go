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
	resolver := test.NewInMemoryResolver()
	userIdentity, agentIdentity := test.SetupIdentitiesForAuth(resolver, false, true)

	err := register.ValidateAllowedForControl(resolver, agentIdentity.Issuer(), userIdentity.Did())
	assert.ErrorContains(t, err, "not allowed")
}

func Test_validate_allowed_for_control_raises_not_allowed_if_not_allowed_for_auth(t *testing.T) {
	resolver := test.NewInMemoryResolver()
	userIdentity, agentIdentity := test.SetupIdentitiesForAuth(resolver, false, false)

	err := register.ValidateAllowedForAuth(resolver, agentIdentity.Issuer(), userIdentity.Did())
	assert.ErrorContains(t, err, "not allowed")
}

func Test_can_validate_allowed_for_control_on_owned_doc(t *testing.T) {
	resolver := test.NewInMemoryResolver()
	userIdentity, _ := test.SetupIdentitiesForAuth(resolver, false, false)

	err := register.ValidateAllowedForControl(resolver, userIdentity.Issuer(), userIdentity.Did())
	assert.NilError(t, err)
}

func Test_can_validate_allowed_for_authentication_on_owned_doc(t *testing.T) {
	resolver := test.NewInMemoryResolver()
	userIdentity, _ := test.SetupIdentitiesForAuth(resolver, false, false)

	err := register.ValidateAllowedForAuth(resolver, userIdentity.Issuer(), userIdentity.Did())
	assert.NilError(t, err)
}

func Test_can_validate_allowed_for_control_with_allowed_by_control_delegation(t *testing.T) {
	resolver := test.NewInMemoryResolver()
	userIdentity, agentIdentity := test.SetupIdentitiesForAuth(resolver, true, false)

	err := register.ValidateAllowedForControl(resolver, agentIdentity.Issuer(), userIdentity.Did())
	assert.NilError(t, err)
}

func Test_can_validate_allowed_for_control_with_allowed_by_auth_delegation(t *testing.T) {
	resolver := test.NewInMemoryResolver()
	userIdentity, agentIdentity := test.SetupIdentitiesForAuth(resolver, false, true)

	err := register.ValidateAllowedForAuth(resolver, agentIdentity.Issuer(), userIdentity.Did())
	assert.NilError(t, err)
}

func Test_can_validate_allowed_for_control_with_controller_doc(t *testing.T) {
	resolver := test.NewInMemoryResolver()
	userIdentity, agentIdentity := test.SetupIdentitiesForAuth(resolver, false, false)

	advancedapi.SetDocumentController(resolver, userIdentity, agentIdentity.Issuer())

	err := register.ValidateAllowedForControl(resolver, agentIdentity.Issuer(), userIdentity.Did())
	assert.NilError(t, err)
}

func Test_can_validate_allowed_for_auth_with_controller_doc(t *testing.T) {
	resolver := test.NewInMemoryResolver()
	userIdentity, agentIdentity := test.SetupIdentitiesForAuth(resolver, false, false)

	advancedapi.SetDocumentController(resolver, userIdentity, agentIdentity.Issuer())

	err := register.ValidateAllowedForAuth(resolver, agentIdentity.Issuer(), userIdentity.Did())
	assert.NilError(t, err)
}

func Test_validate_allowed_for_control_raises_not_allowed_if_resolver_error(t *testing.T) {
	resolver := test.NewInMemoryResolver()
	_, agentIdentity := test.SetupIdentitiesForAuth(resolver, false, false)

	err := register.ValidateAllowedForAuth(resolver, agentIdentity.Issuer(), test.ValidDid)
	assert.ErrorContains(t, err, "document not found")
}

func Test_validate_allowed_for_auth_raises_not_allowed_if_resolver_error(t *testing.T) {

}

/*
# Initialised without the docs so a not found will be raised
resolver_client = ResolverClientTest(docs={})
with pytest.raises(IdentityNotAllowed) as err_wrapper:
is_validator_run_success(IdentityAuthValidation.validate_allowed_for_auth,
resolver_client, issuer=allowed_issuer,
subject_id=allowed_issuer_doc.did)
assert isinstance(err_wrapper.value.__cause__, IdentityResolverError)
*/

func Test_can_verify_authentication(t *testing.T) {
	resolver := test.NewInMemoryResolver()
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
	resolver := test.NewInMemoryResolver()
	_, err := register.VerifyAuthentication(resolver, "invalid token")
	assert.ErrorContains(t, err, "failed to parse token")
}

func Test_verify_authentication_raises_auth_error_if_token_with_missing_data(t *testing.T) {

}

/*
token_with_missing_data = jwt.encode({'plop': 'data'}, valid_private_key, algorithm=TOKEN_ALGORITHM)
resolver_client = ResolverClientTest(docs={authentication_subject_doc.did: authentication_subject_doc})
with pytest.raises(IdentityAuthenticationFailed) as err_wrapper:
IdentityAuthValidation.verify_authentication(resolver_client, token=token_with_missing_data)
assert isinstance(err_wrapper.value.__cause__, IdentityValidationError)
*/

func Test_verify_authentication_raises_auth_error_if_invalid_issuer(t *testing.T) {

}

/*
token_with_invalid_iss = JwtTokenHelper.create_auth_token(iss='invalid issuer',
sub=authentication_subject_doc.did,
aud='http://audience/',
duration=360,
private_key=valid_private_key)

resolver_client = ResolverClientTest(docs={authentication_subject_doc.did: authentication_subject_doc})
with pytest.raises(IdentityAuthenticationFailed) as err_wrapper:
IdentityAuthValidation.verify_authentication(resolver_client, token=token_with_invalid_iss)
assert isinstance(err_wrapper.value.__cause__, IdentityValidationError)
*/

func Test_verify_authentication_raises_auth_error_if_resolver_error(t *testing.T) {

}

/*
# doc not provided so will raise not found
resolver_client = ResolverClientTest(docs={})
with pytest.raises(IdentityAuthenticationFailed) as err_wrapper:
IdentityAuthValidation.verify_authentication(resolver_client, token=valid_auth_token)
assert isinstance(err_wrapper.value.__cause__, IdentityResolverError)
*/

func Test_verify_authentication_raises_auth_error_if_issuer_not_in_doc_keys_or_deleg(t *testing.T) {

}

/*
not_auth_issuer = Issuer.build(authentication_subject_doc.did, '#OtherIssuer')
token_from_not_auth_issuer = JwtTokenHelper.create_auth_token(
iss=str(not_auth_issuer),
sub=authentication_subject_doc.did,
aud='http://audience/',
duration=360,
private_key=valid_private_key
)
resolver_client = ResolverClientTest(docs={authentication_subject_doc.did: authentication_subject_doc})
with pytest.raises(IdentityAuthenticationFailed) as err_wrapper:
IdentityAuthValidation.verify_authentication(resolver_client, token=token_from_not_auth_issuer)
assert isinstance(err_wrapper.value.__cause__, IdentityInvalidRegisterIssuerError)
*/

func Test_verify_authentication_raises_auth_error_if_token_invalid_signature(t *testing.T) {

}

/*
token_signed_with_an_other_private_key = JwtTokenHelper.create_auth_token(
iss=str(allowed_issuer),
sub=authentication_subject_doc.did,
aud='http://audience/',
duration=360,
private_key=other_private_key
)
resolver_client = ResolverClientTest(docs={authentication_subject_doc.did: authentication_subject_doc})
with pytest.raises(IdentityAuthenticationFailed) as err_wrapper:
IdentityAuthValidation.verify_authentication(resolver_client, token=token_signed_with_an_other_private_key)
assert isinstance(err_wrapper.value.__cause__, IdentityValidationError)
*/

func Test_verify_authentication_raises_auth_error_if_token_not_allowed(t *testing.T) {
	resolver := test.NewInMemoryResolver()
	userIdentity, agentIdentity := test.SetupIdentitiesForAuth(resolver, false, false)

	duration, _ := time.ParseDuration("300s")
	token, err := register.CreateAuthToken(agentIdentity.Issuer(), userIdentity.Did(), "audience", duration, agentIdentity.KeyPair().PrivateKey, 0)
	assert.NilError(t, err)

	_, err = register.VerifyAuthentication(resolver, token)
	assert.ErrorContains(t, err, "not allowed")
}
