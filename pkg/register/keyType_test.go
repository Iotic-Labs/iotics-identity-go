// Copyright (c) IOTIC LABS LIMITED. All rights reserved. Licensed under the Apache License, Version 2.0.

package register_test

import (
	"testing"

	"github.com/Iotic-Labs/iotics-identity-go/pkg/register"
	"gotest.tools/assert"
)

func Test_NewKeyType(t *testing.T) {
	kType, err := register.NewKeyType("Secp256k1VerificationKey2018")
	assert.NilError(t, err)
	assert.Check(t, kType == register.PublicKeyType)

	kType, err = register.NewKeyType("Secp256k1SignatureAuthentication2018")
	assert.NilError(t, err)
	assert.Check(t, kType == register.AuthenticationKeyType)

	_, err = register.NewKeyType("not found")
	assert.ErrorContains(t, err, "invalid key type")
}
