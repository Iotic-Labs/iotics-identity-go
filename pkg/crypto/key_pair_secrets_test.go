// Copyright (c) IOTIC LABS LIMITED. All rights reserved. Licensed under the Apache License, Version 2.0.

package crypto_test

import (
	"strings"
	"testing"

	"github.com/Iotic-Labs/iotics-identity-go/v2/pkg/test"

	id "github.com/Iotic-Labs/iotics-identity-go/v2/pkg/identity"

	"github.com/ethereum/go-ethereum/crypto/secp256k1"

	"github.com/Iotic-Labs/iotics-identity-go/v2/pkg/crypto"
	"github.com/tyler-smith/go-bip39"
	"github.com/tyler-smith/go-bip39/wordlists"
	"gotest.tools/assert"
)

func Test_can_create_key_pair_secrets_with_none_seed_method(t *testing.T) {
	password := "a password"
	keyPair, err := crypto.NewKeyPairSecrets(test.ValidSeed16B, test.ValidKeyPairPath, crypto.SeedMethodNone, password)

	assert.NilError(t, err)
	assert.Equal(t, string(keyPair.Seed()), string(test.ValidSeed16B))
	assert.Equal(t, keyPair.Path(), test.ValidKeyPairPath)
	assert.Equal(t, keyPair.SeedMethod(), crypto.SeedMethodNone)
	assert.Equal(t, keyPair.Password(), password)
}

func Test_can_create_key_pair_secrets_with_default_bip39_seed_method(t *testing.T) {
	password := "a password"
	keyPair, err := crypto.NewDefaultKeyPairSecretsWithPassword(test.ValidBip39Seed32B, test.ValidKeyPairPath, password)

	assert.NilError(t, err)
	assert.Equal(t, string(keyPair.Seed()), string(test.ValidBip39Seed32B))
	assert.Equal(t, keyPair.Path(), test.ValidKeyPairPath)
	assert.Equal(t, keyPair.SeedMethod(), crypto.SeedMethodBip39)
	assert.Equal(t, keyPair.Password(), password)
}

func Test_create_key_pair_raises_validation_error_if_invalid_seed_with_bip39_method(t *testing.T) {
	cases := []struct {
		seed []byte
		msg  string
	}{
		{[]byte(strings.Repeat("too long", 945)), "invalid seed for bip39"},
		{[]byte(""), "invalid seed for bip39"},
	}
	for _, c := range cases {
		_, err := crypto.NewDefaultKeyPairSecrets(c.seed, test.ValidKeyPairPath)
		assert.ErrorContains(t, err, c.msg)
	}
}

func Test_create_key_pair_raises_validation_error_if_invalid_seed_with_none_method(t *testing.T) {
	cases := []struct {
		seed []byte
		msg  string
	}{
		{[]byte("not long enough")[:3], "invalid seed length"},
		{[]byte(""), "invalid seed length"},
	}
	for _, c := range cases {
		_, err := crypto.NewKeyPairSecrets(c.seed, test.ValidKeyPairPath, crypto.SeedMethodNone, "")
		assert.ErrorContains(t, err, c.msg)
	}
}

func Test_create_key_pair_raises_validation_error_if_invalid_path(t *testing.T) {
	invalidPath := "invalid path (no starting with Iotics prefix)"
	_, err := crypto.NewDefaultKeyPairSecrets(test.ValidBip39Seed32B, invalidPath)
	assert.ErrorContains(t, err, "invalid key pair path")
}

func Test_create_key_pair_with_purpose(t *testing.T) {
	name := "a_name"
	password := ""

	cases := []struct {
		didType id.DidType
	}{
		{id.Host},
		{id.User},
		{id.Agent},
		{id.Twin},
	}
	for _, c := range cases {
		path := crypto.PathForDIDType(name, c.didType)
		keyPair, err := crypto.NewKeyPairSecrets(test.ValidBip39Seed32B, path, crypto.SeedMethodNone, password)
		assert.NilError(t, err)
		assert.Equal(t, string(keyPair.Seed()), string(test.ValidBip39Seed32B))
		assert.Equal(t, keyPair.Path(), path)
		assert.Equal(t, keyPair.SeedMethod(), crypto.SeedMethodNone)
		assert.Equal(t, keyPair.Password(), password)
	}
}

func Test_can_convert_seed_to_mnemonic(t *testing.T) {
	bip39.SetWordList(wordlists.English)
	mnemonic, err := crypto.SeedBip39ToMnemonic(test.ValidBip39Seed32B)
	assert.NilError(t, err)
	assert.Equal(t, mnemonic, test.ValidMnemonicEnglish)
}

func Test_can_convert_seed_to_mnemonic_with_spanish(t *testing.T) {
	bip39.SetWordList(wordlists.Spanish)
	mnemonic, err := crypto.SeedBip39ToMnemonic(test.ValidBip39Seed32B)
	assert.NilError(t, err)
	assert.Equal(t, mnemonic, "glaciar mojar rueda hueso exponer chupar tanque hijo grano olvido ensayo gaita inmune percha retrato rojo cielo alivio fiel retrato brusco chupar sirena peine")
}

func Test_convert_seed_to_mnemonic_raises_validation_error_if_invalid_seed(t *testing.T) {
	bip39.SetWordList(wordlists.English)
	cases := []struct {
		seed []byte
		msg  string
	}{
		{[]byte("not long enough")[:3], "Entropy length must be [128, 256] and a multiple of 32"},
		{[]byte(""), "Entropy length must be [128, 256] and a multiple of 32"},
	}
	for _, c := range cases {
		_, err := crypto.SeedBip39ToMnemonic(c.seed)
		assert.ErrorContains(t, err, c.msg)
	}
}

func Test_can_convert_mnemonic_to_seed(t *testing.T) {
	bip39.SetWordList(wordlists.English)
	seed, err := crypto.MnemonicBip39ToSeed(test.ValidMnemonicEnglish)
	assert.NilError(t, err)
	assert.Equal(t, string(seed), string(test.ValidBip39Seed32B))
}

func Test_can_convert_mnemonic_to_seed_with_spanish(t *testing.T) {
	bip39.SetWordList(wordlists.Spanish)
	seed, err := crypto.MnemonicBip39ToSeed(test.ValidMnemonicSpanish)
	assert.NilError(t, err)
	assert.Equal(t, string(seed), string(test.ValidBip39Seed32B))
}

func Test_convert_mnemonic_to_seed_raises_validation_error_if_invalid_seed(t *testing.T) {
	bip39.SetWordList(wordlists.English)
	cases := []struct {
		mnemonic string
	}{
		{strings.Repeat("flee", 10)},
		{strings.Repeat("flee", 32)},
	}
	for _, c := range cases {
		_, err := crypto.MnemonicBip39ToSeed(c.mnemonic)
		assert.ErrorContains(t, err, "Invalid mnenomic")
	}
}

func Test_validate_bip39_seed_should_not_raise_if_valid_seed(t *testing.T) {
	err := crypto.ValidateBip39Seed(test.ValidBip39Seed32B)
	assert.NilError(t, err)
}

func Test_validate_bip39_seed_should_raise_if_invalid_seed(t *testing.T) {
	err := crypto.ValidateBip39Seed([]byte("invalid"))
	assert.ErrorContains(t, err, "Entropy length must be [128, 256] and a multiple of 32")
}

func Test_can_get_private_key_from_key_pair_secrets_bip39(t *testing.T) {
	const expectedBitSize = 256
	validKeyPairSecrets, _ := crypto.NewKeyPairSecrets(test.ValidBip39Seed32B, test.ValidKeyPairPath, crypto.SeedMethodBip39, "")

	privateKey, err := crypto.GetPrivateKey(validKeyPairSecrets)

	assert.NilError(t, err)
	assert.Assert(t, privateKey != nil)

	curve := privateKey.PublicKey.Curve.(*secp256k1.BitCurve)
	assert.Assert(t, curve != nil)
	assert.Assert(t, curve.BitSize == expectedBitSize)
	assert.Assert(t, curve.IsOnCurve(privateKey.X, privateKey.Y))
}

func Test_can_get_private_key_from_key_pair_secrets_none(t *testing.T) {
	const expectedBitSize = 256
	validKeyPairSecrets, _ := crypto.NewKeyPairSecrets(test.ValidBip39Seed32B, test.ValidKeyPairPath, crypto.SeedMethodNone, "")

	privateKey, err := crypto.GetPrivateKey(validKeyPairSecrets)

	assert.NilError(t, err)
	assert.Assert(t, privateKey != nil)

	curve := privateKey.PublicKey.Curve.(*secp256k1.BitCurve)
	assert.Assert(t, curve != nil)
	assert.Assert(t, curve.BitSize == expectedBitSize)
	assert.Assert(t, curve.IsOnCurve(privateKey.X, privateKey.Y))
}

func Test_can_get_public_base58_key(t *testing.T) {
	bip39.SetWordList(wordlists.Spanish)
	validKeyPairSecrets, _ := crypto.NewKeyPairSecrets(test.ValidBip39Seed32B, test.ValidKeyPairPath, crypto.SeedMethodBip39, "")
	publicKeyBase58, err := crypto.GetPublicKeyBase58FromKeyPairSecrets(validKeyPairSecrets)
	assert.NilError(t, err)
	expectedBase58 := "QUxw9SXsLmwhYYUubXGJHJ6AHmpzDdfzx85aU5ryKC1nF15dh98PAC9XbKXCqBbSyqmejbT5PZJZmJ74z5LP1U2W"
	assert.Equal(t, publicKeyBase58, expectedBase58)
}

func Test_can_get_key_pair(t *testing.T) {
	validKeyPairSecrets, _ := crypto.NewKeyPairSecrets(test.ValidBip39Seed32B, test.ValidKeyPairPath, crypto.SeedMethodBip39, "")
	privateKeyPair, _ := crypto.GetKeyPair(validKeyPairSecrets)
	publicKeyBase58, _ := crypto.GetPublicKeyBase58FromKeyPairSecrets(validKeyPairSecrets)
	assert.Equal(t, privateKeyPair.PublicKeyBase58, publicKeyBase58)
}
