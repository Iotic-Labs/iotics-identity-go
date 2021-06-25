// Copyright (c) IOTIC LABS LIMITED. All rights reserved. Licensed under the Apache License, Version 2.0.

package register_test

import (
	"github.com/Iotic-Labs/iotics-identity-go/pkg/test"
	"testing"

	"github.com/Iotic-Labs/iotics-identity-go/pkg/register"
	"gotest.tools/assert"
)

func Test_can_build_issuer(t *testing.T) {
	expectedIssuer := &register.Issuer{
		Did:  test.ValidDid,
		Name: test.ValidName,
	}
	issuer, err := register.NewIssuer(test.ValidDid, test.ValidName)
	assert.NilError(t, err)
	assert.DeepEqual(t, issuer, expectedIssuer)
}

func Test_can_build_issuer_from_string(t *testing.T) {
	expectedIssuer := &register.Issuer{
		Did:  test.ValidDid,
		Name: test.ValidName,
	}
	issuer, err := register.NewIssuerFromString(test.ValidDid + test.ValidName)
	assert.NilError(t, err)
	assert.DeepEqual(t, issuer, expectedIssuer)
}

func Test_building_issuer_with_invalid_name_raises_validation_error(t *testing.T) {
	issuer, err := register.NewIssuer(test.ValidDid, "invalidName")
	assert.Equal(t, issuer == nil, true)
	assert.ErrorContains(t, err, "invalid name")
}

func Test_building_issuer_from_string_with_invalid_name_raises_validation_error(t *testing.T) {
	issuer, err := register.NewIssuerFromString(test.ValidDid + "#invalid name")
	assert.Equal(t, issuer == nil, true)
	assert.ErrorContains(t, err, "invalid name")
}

func Test_building_issuer_with_invalid_did_raises_validation_error(t *testing.T) {
	issuer, err := register.NewIssuer("invalidDid", test.ValidName)
	assert.Equal(t, issuer == nil, true)
	assert.ErrorContains(t, err, "invalid identifier")
}

func Test_building_issuer_from_string_with_invalid_did_raises_validation_error(t *testing.T) {
	issuer, err := register.NewIssuerFromString("invalidDid" + test.ValidName)
	assert.Equal(t, issuer == nil, true)
	assert.ErrorContains(t, err, "invalid identifier")
}

func Test_can_build_issuer_from_string_with_invalid_string_raises_validation_error(t *testing.T) {
	issuer, err := register.NewIssuerFromString(test.ValidDid + "aNameWithoutSep")
	assert.Equal(t, issuer == nil, true)
	assert.ErrorContains(t, err, "invalid issuer")
}

func Test_can_build_issuer_key(t *testing.T) {
	issuer, _ := register.NewIssuer(test.ValidDid, test.ValidName)
	expectedIssuerKey := &register.IssuerKey{
		Issuer:          issuer,
		PublicKeyBase58: test.ValidPublicBase58,
	}
	issuerKey, err := register.NewIssuerKey(test.ValidDid, test.ValidName, test.ValidPublicBase58)
	assert.NilError(t, err)
	assert.DeepEqual(t, issuerKey, expectedIssuerKey)
}

func Test_building_issuer_key_with_invalid_issuer_data_raises_validation_error(t *testing.T) {
	issuer, err := register.NewIssuerKey("invalid did", test.ValidName, test.ValidPublicBase58)
	assert.Equal(t, issuer == nil, true)
	assert.ErrorContains(t, err, "invalid identifier")
}
