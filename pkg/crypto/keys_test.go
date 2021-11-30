// Copyright (c) IOTIC LABS LIMITED. All rights reserved. Licensed under the Apache License, Version 2.0.

package crypto_test

import (
	"encoding/hex"
	"testing"

	"github.com/Iotic-Labs/iotics-identity-go/pkg/test"

	"github.com/Iotic-Labs/iotics-identity-go/pkg/crypto"
	"github.com/fomichev/secp256k1"
	"github.com/jbenet/go-base58"
	"gotest.tools/assert"
)

func Test_get_private_ecdsa(t *testing.T) {
	privateKey, err := crypto.GetPrivateKeyFromExponent(test.PrivateExponentHex)
	assert.NilError(t, err)
	assert.Check(t, privateKey != nil)
}

func Test_get_public_keys_from_private_ecdsa(t *testing.T) {
	privateKey, err := crypto.GetPrivateKeyFromExponent(test.PrivateExponentHex)
	assert.NilError(t, err)
	publicKeyBytesDer, publicKeyBase58, err := crypto.GetPublicKeysFromPrivateKey(privateKey)
	assert.NilError(t, err)
	assert.Equal(t, hex.EncodeToString(base58.DecodeAlphabet(publicKeyBase58, base58.BTCAlphabet)),
		hex.EncodeToString(publicKeyBytesDer))
}

func Test_get_public_ecdsa_from_base58(t *testing.T) {
	publicKey, err := crypto.GetPublicKeyFromBase58(test.ValidPublicBase58)
	assert.NilError(t, err)
	assert.Assert(t, publicKey != nil)

	curve := secp256k1.SECP256K1()
	assert.Assert(t, curve.IsOnCurve(publicKey.X, publicKey.Y))
}

func Test_get_public_ecdsa_from_base58_raises_validation_error_if_invalid_key(t *testing.T) {
	invalidPublicBase58 := test.ValidPublicBase58 + "a"
	_, err := crypto.GetPublicKeyFromBase58(invalidPublicBase58)
	assert.ErrorContains(t, err, "invalid secp256k1 public key")
}
