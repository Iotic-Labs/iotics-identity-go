// Copyright (c) IOTIC LABS LIMITED. All rights reserved. Licensed under the Apache License, Version 2.0.

package main_test

import (
	"context"
	"encoding/hex"
	"fmt"

	"github.com/Iotic-Labs/iotics-identity-go/v2/pkg/advancedapi"
	"github.com/Iotic-Labs/iotics-identity-go/v2/pkg/crypto"
	"github.com/Iotic-Labs/iotics-identity-go/v2/pkg/identity"
	"github.com/Iotic-Labs/iotics-identity-go/v2/pkg/register"
	"github.com/go-bdd/gobdd"
	"gotest.tools/assert"
)

func assertNewDocAndIdentity(t gobdd.StepTest, _ gobdd.Context, seed []byte, keyName string, issuerName string, doc *register.RegisterDocument, id register.RegisteredIdentity) {
	assert.Assert(t, doc != nil)
	assert.Assert(t, id != nil)

	err := advancedapi.ValidateRegisterDocument(context.TODO(), resolver, doc)
	assert.NilError(t, err)

	didType, _ := identity.ParseDidType(doc.IoticsDIDType)
	assertNewlyCreatedRegisteredIdentity(t, seed, keyName, issuerName, id, didType)

	assertOwnerKey(t, doc, issuerName, id)
}

func assertNewlyCreatedRegisteredIdentity(t gobdd.StepTest, seed []byte, keyName string, identityName string, registeredIdentity register.RegisteredIdentity, purpose identity.DidType) {
	path := crypto.PathForDIDType(keyName, purpose)
	seedString, _ := hex.DecodeString(string(seed))
	expectedSecret, err := crypto.NewDefaultKeyPairSecrets(seedString, path)
	assert.NilError(t, err)
	expectedKeyPair, err := crypto.GetKeyPair(expectedSecret)
	assert.NilError(t, err)
	expectedDid, err := advancedapi.CreateIdentifier(expectedKeyPair.PublicKeyBytes)
	assert.NilError(t, err)
	assert.Assert(t, expectedDid != "")

	assert.Assert(t, registeredIdentity.Did() == expectedDid, fmt.Sprintf("%s != %s", registeredIdentity.Did(), expectedDid))
	assert.Assert(t, registeredIdentity.Name() == identityName, fmt.Sprintf("%s != %s", registeredIdentity.Name(), identityName))
	assert.Assert(t, registeredIdentity.KeyPair().PublicKeyBase58 == expectedKeyPair.PublicKeyBase58, fmt.Sprintf("%s != %s", registeredIdentity.KeyPair().PublicKeyBase58, expectedKeyPair.PublicKeyBase58))
}

func assertOwnerKey(t gobdd.StepTest, doc *register.RegisterDocument, ownerName string, identity register.RegisteredIdentity) {
	keyPair := identity.KeyPair()
	assertOwnerPubKeyExist(t, doc, ownerName, keyPair.PublicKeyBase58)
}

func assertOwnerPubKeyExist(t gobdd.StepTest, doc *register.RegisterDocument, ownerName string, publicKeyBase58 string) {
	ownerKey := doc.PublicKeyByID(ownerName)
	assert.Assert(t, ownerKey != nil, fmt.Sprintf("owner key %s not found in the register document", ownerName))
	assert.Assert(t, ownerKey.Revoked == false, "owner key should not be revoked")
	assert.Assert(t, ownerKey.PublicKeyBase58 == publicKeyBase58, "invalid owner public key base58")
}
