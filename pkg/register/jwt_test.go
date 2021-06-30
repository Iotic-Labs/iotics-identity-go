// Copyright (c) IOTIC LABS LIMITED. All rights reserved. Licensed under the Apache License, Version 2.0.

package register_test

import (
	"crypto/ecdsa"
	"testing"
	"time"

	"github.com/Iotic-Labs/iotics-identity-go/pkg/advancedapi"
	"github.com/Iotic-Labs/iotics-identity-go/pkg/test"

	"github.com/Iotic-Labs/iotics-identity-go/pkg/register"

	"gotest.tools/assert"
)

func compareDocs(t *testing.T, registerDoc *register.RegisterDocument, otherDoc *register.RegisterDocument) bool {
	opts := []register.RegisterDocumentOpts{
		register.AddFromExistingDocument(otherDoc),
	}
	otherDocFull, _ := register.NewRegisterDocument(opts)

	// Ensure UpdateTime is same
	otherDocFull.UpdateTime = registerDoc.UpdateTime

	assert.DeepEqual(t, registerDoc, otherDocFull)

	return true
}

func Test_can_create_doc_token(t *testing.T) {
	registerDocument, issuer, keypair := test.HelperGetRegisterDocument()
	result, err := register.CreateDocumentToken(issuer, "audience", registerDocument, keypair.PrivateKey)
	assert.NilError(t, err)
	assert.Check(t, len(result) != 0)
}

func Test_create_doc_token_raises_validation_error_if_can_not_create_token(t *testing.T) {
	registerDocument, issuer, _ := test.HelperGetRegisterDocument()
	invalidPrivateKey := &ecdsa.PrivateKey{}

	_, err := register.CreateDocumentToken(issuer, "audience", registerDocument, invalidPrivateKey)
	assert.ErrorContains(t, err, "invalid private key")
}

func Test_can_decode_doc_token_no_verify(t *testing.T) {
	registerDocument, issuer, keypair := test.HelperGetRegisterDocument()
	result, _ := register.CreateDocumentToken(issuer, test.ValidAudience, registerDocument, keypair.PrivateKey)
	decodedDocument, err := register.DecodeDocumentTokenNoVerify(result)
	assert.NilError(t, err)
	assert.Assert(t, compareDocs(t, registerDocument, decodedDocument.Doc))
	assert.DeepEqual(t, issuer, decodedDocument.Issuer)
	assert.Assert(t, test.ValidAudience == decodedDocument.Audience)
}

func Test_can_decode_and_verify_doc_token(t *testing.T) {
	registerDocument, issuer, keypair := test.HelperGetRegisterDocument()
	result, _ := register.CreateDocumentToken(issuer, test.ValidAudience, registerDocument, keypair.PrivateKey)
	decodedDocument, err := register.DecodeDocumentToken(result, keypair.PublicKeyBase58, test.ValidAudience)
	assert.NilError(t, err)
	assert.Assert(t, compareDocs(t, registerDocument, decodedDocument.Doc))
	assert.DeepEqual(t, issuer, decodedDocument.Issuer)
	assert.Assert(t, test.ValidAudience == decodedDocument.Audience)
}

func Test_can_create_auth_token(t *testing.T) {
	duration, _ := time.ParseDuration("123s")
	token, err := register.CreateAuthToken(test.ValidIssuer, test.OtherDid, test.ValidAudience, duration, test.ValidPrivateKey, 0)
	assert.NilError(t, err)
	assert.Check(t, len(token) > 1)
}

func Test_create_auth_token_raises_validation_error_if_can_not_create_token(t *testing.T) {

}

/*with pytest.raises(IdentityValidationError):
JwtTokenHelper.create_auth_token(iss=str(valid_issuer),
sub='did:iotics:iotHjrmKpPGWyEC4FFo4d6oyzVVk6MXLmEEE',
aud='http://somehting',
duration=12,
private_key='no a private key')*/

func Test_create_auth_token_raises_validation_error_if_negative_duration(t *testing.T) {

}

/*with pytest.raises(IdentityValidationError):
JwtTokenHelper.create_auth_token(iss=str(valid_issuer),
sub='did:iotics:iotHjrmKpPGWyEC4FFo4d6oyzVVk6MXLmEEE',
aud='http://somehting',
duration=-12,
private_key=valid_private_key)*/

func Test_can_decode_auth_token(t *testing.T) {
	duration, _ := time.ParseDuration("123s")
	token, err := register.CreateAuthToken(test.ValidIssuer, test.OtherDid, test.ValidAudience, duration, test.ValidPrivateKey, 0)
	assert.NilError(t, err)
	assert.Check(t, len(token) > 1)

	authClaims, err := register.DecodeAuthTokenNoVerify(token)
	assert.Equal(t, authClaims.Audience, test.ValidAudience)
	assert.DeepEqual(t, authClaims.Issuer, test.ValidIssuer)
	assert.Equal(t, authClaims.ExpiresAt-authClaims.IssuedAt, int64(duration.Seconds()))
	assert.Equal(t, authClaims.Subject, test.OtherDid)
}

func Test_can_decode_and_verify_auth_token(t *testing.T) {
	duration, _ := time.ParseDuration("123s")
	token, err := register.CreateAuthToken(test.ValidIssuer, test.OtherDid, test.ValidAudience, duration, test.ValidPrivateKey, 0)
	assert.NilError(t, err)
	assert.Check(t, len(token) > 1)

	authClaims, err := register.DecodeAuthToken(token, test.ValidKeyPair.PublicKeyBase58, test.ValidAudience)
	assert.Equal(t, authClaims.Audience, test.ValidAudience)
	assert.DeepEqual(t, authClaims.Issuer, test.ValidIssuer)
	assert.Equal(t, authClaims.ExpiresAt-authClaims.IssuedAt, int64(duration.Seconds()))
	assert.Equal(t, authClaims.Subject, test.OtherDid)
}

func Test_decode_token_raises_validation_error_if_invalid_token(t *testing.T) {
	_, err := register.DecodeAuthTokenNoVerify("not a real token")
	assert.ErrorContains(t, err, "failed to parse token")
}

func Test_decode_and_verify_token_raises_validation_error_if_invalid_token(t *testing.T) {
	_, err := register.DecodeAuthToken("not a real token..", "", "")
	assert.ErrorContains(t, err, "illegal base64 data at input byte 3")
}

func Test_decode_and_verify_token_raises_validation_error_if_invalid_issuer_key(t *testing.T) {

}

/*audience = 'http://something'
token = JwtTokenHelper.create_doc_token(issuer=valid_issuer_key.issuer,
audience=audience,
doc=register_doc,
private_key=valid_private_key)

with pytest.raises(IdentityValidationError):
_, public_base58 = KeysHelper.get_public_keys_from_private_ECDSA(other_private_key)
JwtTokenHelper.decode_and_verify_token(token, public_base58, audience)*/

func Test_create_challenge_token(t *testing.T) {
	resolver := test.NewInMemoryResolverEmpty()
	userIdentity, agentIdentity := test.SetupIdentitiesForAuth(resolver, false, true)

	proof, err := advancedapi.CreateProof(test.ValidKeyPair2, agentIdentity.Issuer(), []byte(userIdentity.Did()))

	token, err := register.CreateChallengeToken(proof, test.ValidKeyPair2.PrivateKey)
	assert.NilError(t, err)
	assert.Check(t, len(string(token)) > 0)
}

func Test_decode_challenge_token_no_verify(t *testing.T) {
	resolver := test.NewInMemoryResolverEmpty()
	userIdentity, agentIdentity := test.SetupIdentitiesForAuth(resolver, false, true)

	proof, err := advancedapi.CreateProof(test.ValidKeyPair2, agentIdentity.Issuer(), []byte(userIdentity.Did()))

	token, err := register.CreateChallengeToken(proof, test.ValidKeyPair2.PrivateKey)
	assert.NilError(t, err)
	assert.Check(t, len(string(token)) > 0)

	claims, err := register.DecodeChallengeTokenNoVerify(token)
	assert.NilError(t, err)
	assert.DeepEqual(t, claims.Issuer, agentIdentity.Issuer())
}

func Test_decode_challenge_token(t *testing.T) {
	resolver := test.NewInMemoryResolverEmpty()
	userIdentity, agentIdentity := test.SetupIdentitiesForAuth(resolver, false, true)

	proof, err := advancedapi.CreateProof(test.ValidKeyPair2, agentIdentity.Issuer(), []byte(userIdentity.Did()))

	token, err := register.CreateChallengeToken(proof, test.ValidKeyPair2.PrivateKey)
	assert.NilError(t, err)
	assert.Check(t, len(string(token)) > 0)

	claims, err := register.DecodeChallengeToken(token, test.ValidKeyPair2.PublicKeyBase58, userIdentity.Did())
	assert.NilError(t, err)
	assert.DeepEqual(t, claims.Issuer, agentIdentity.Issuer())
}
