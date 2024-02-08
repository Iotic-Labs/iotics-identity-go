// Copyright (c) IOTIC LABS LIMITED. All rights reserved. Licensed under the Apache License, Version 2.0.

package crypto_test

import (
	"testing"

	"github.com/Iotic-Labs/iotics-identity-go/v3/pkg/crypto"
	"gotest.tools/assert"
)

func Test_CreateSeed(t *testing.T) {
	_, err := crypto.CreateSeed(128)
	assert.NilError(t, err)
	_, err = crypto.CreateSeed(256)
	assert.NilError(t, err)

	_, err = crypto.CreateSeed(333)
	assert.ErrorContains(t, err, "length must be 128 or 256")
}
