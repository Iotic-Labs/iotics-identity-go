// Copyright (c) IOTIC LABS LIMITED. All rights reserved. Licensed under the Apache License, Version 2.0.

package identity_test

import (
	"fmt"
	"strings"
	"testing"

	"github.com/Iotic-Labs/iotics-identity-go/v3/pkg/test"

	"github.com/Iotic-Labs/iotics-identity-go/v3/pkg/identity"
	"github.com/Iotic-Labs/iotics-identity-go/v3/pkg/validation"
	"gotest.tools/assert"
)

func Test_can_make_identifier(t *testing.T) {
	id, err := identity.MakeIdentifier(test.ValidKeyPair.PublicKeyBytes)
	assert.NilError(t, err)
	assert.Equal(t, strings.HasPrefix(id, validation.IdentifierPrefix), true)
}

func Test_cannot_make_identifier_bad_publickey(t *testing.T) {
	_, err := identity.MakeIdentifier([]byte{})
	assert.ErrorContains(t, err, "public key bytes wrong length 0 != 65")
}

func Test_make_identifier_is_idempotent(t *testing.T) {
	id1, err1 := identity.MakeIdentifier(test.ValidKeyPair.PublicKeyBytes)
	assert.NilError(t, err1)
	id2, err2 := identity.MakeIdentifier(test.ValidKeyPair.PublicKeyBytes)
	assert.NilError(t, err2)
	assert.Equal(t, id1, id2)
}

func Test_is_same_identifier_return_true_for_the_same_identifier_ignoring_names(t *testing.T) {
	data := []struct {
		id1 string
		id2 string
	}{
		{test.ValidDid, test.ValidDid},
		{test.ValidDid, fmt.Sprintf("%s#Plop", test.ValidDid)},
		{fmt.Sprintf("%s#Plop", test.ValidDid), test.ValidDid},
		{fmt.Sprintf("%s#AAA", test.ValidDid), fmt.Sprintf("%s#BBB", test.ValidDid)},
	}
	for _, d := range data {
		result := identity.IsSameIdentifier(d.id1, d.id2)
		assert.Equal(t, result, true)
	}
}

func Test_is_same_identifier_return_false_for_different_identifier_ignoring_names(t *testing.T) {
	data := []struct {
		id1 string
		id2 string
	}{
		{test.ValidDid, fmt.Sprintf("%sK", test.ValidDid[:len(test.ValidDid)-1])},
		{fmt.Sprintf("%s#Plop", test.ValidDid), fmt.Sprintf("%sK#Plop", test.ValidDid[:len(test.ValidDid)-1])},
	}
	for _, d := range data {
		result := identity.IsSameIdentifier(d.id1, d.id2)
		assert.Equal(t, result, false)
	}
}

func Test_MakeName(t *testing.T) {
	name := identity.MakeName(identity.Twin)
	assert.Check(t, name == "#twin-0")
}
