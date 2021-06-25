// Copyright (c) IOTIC LABS LIMITED. All rights reserved. Licensed under the Apache License, Version 2.0.

package proof_test

import (
	"crypto/ecdsa"
	"testing"

	"github.com/Iotic-Labs/iotics-identity-go/pkg/test"

	"github.com/Iotic-Labs/iotics-identity-go/pkg/register"
	"gotest.tools/assert"

	"github.com/Iotic-Labs/iotics-identity-go/pkg/proof"
)

func Test_can_build_proof(t *testing.T) {
	proof, err := proof.NewProof(test.ValidPrivateKey, test.ValidIssuer.Did, test.ValidIssuer.Name, test.ValidContent)
	assert.NilError(t, err)
	assert.Equal(t, proof.IssuerDid, test.ValidIssuer.Did)
	assert.Equal(t, proof.IssuerName, test.ValidIssuer.Name)
	assert.Equal(t, string(proof.Content), string(test.ValidContent))
	assert.Equal(t, proof.Signature != "", true)
}

func Test_build_proof_raises_validation_error_if_invalid_inputs(t *testing.T) {
	proof, err := proof.NewProof(&ecdsa.PrivateKey{}, test.ValidIssuer.Did, test.ValidIssuer.Name, test.ValidContent)
	assert.Assert(t, proof == nil)
	assert.ErrorContains(t, err, "invalid private key")
}

func Test_can_build_challenge_token(t *testing.T) {
	token, err := register.CreateChallengeToken(test.ValidProof, test.ValidPrivateKey)
	assert.NilError(t, err)
	assert.Assert(t, len(token) > 0)

	decoded, err := register.DecodeChallengeTokenNoVerify(token)
	assert.NilError(t, err)
	assert.Assert(t, decoded != nil)

	assert.Equal(t, decoded.Issuer.String(), test.ValidIssuer.String())
	assert.Equal(t, decoded.Audience, string(test.ValidContent[:]))
	assert.Equal(t, decoded.Signature, test.ValidProof.Signature)
}

func Test_build_challenge_token_raises_validation_error_if_can_not_create_token(t *testing.T) {

}

func Test_can_build_proof_from_challenge_token(t *testing.T) {
	challengeToken, err := register.CreateChallengeToken(test.ValidProof, test.ValidKeyPair.PrivateKey)
	assert.NilError(t, err)
	assert.Assert(t, challengeToken != "")

	deserialisedToken, err := register.DecodeChallengeToken(challengeToken, test.ValidKeyPair.PublicKeyBase58, "")

	assert.NilError(t, err)
	assert.Assert(t, deserialisedToken != nil)
	assert.Assert(t, deserialisedToken.Signature == test.ValidProof.Signature)
	issuer, _ := register.NewIssuer(test.ValidProof.IssuerDid, test.ValidProof.IssuerName)
	assert.Assert(t, deserialisedToken.Issuer.String() == issuer.String())
	assert.Assert(t, deserialisedToken.Audience == string(test.ValidProof.Content))
}

func Test_build_proof_from_challenge_token_raises_validation_error_if_invalid_token(t *testing.T) {

}

func Test_build_proof_from_challenge_token_raises_validation_error_if_invalid_token_data(t *testing.T) {

}

func Test_build_proof_from_challenge_token_raises_issuer_error_if_issuer_not_in_doc(t *testing.T) {

}
