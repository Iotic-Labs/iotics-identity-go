// Copyright (c) IOTIC LABS LIMITED. All rights reserved. Licensed under the Apache License, Version 2.0.

package validation_test

import (
	"strings"
	"testing"

	"github.com/Iotic-Labs/iotics-identity-go/pkg/validation"
	"gotest.tools/assert"
)

const (
	validDid  = "did:iotics:iotHHHmKpPGWyEC4FFo4d6oyzVVk6MXLmEgY"
	validName = "#aName"
)

func Test_valid_identifier_without_checksum(t *testing.T) {
	err := validation.ValidateIdentifier(validDid)
	assert.ErrorContains(t, err, "checksum does not match")
}

func Test_invalid_identifier(t *testing.T) {
	data := []string{
		"",
		"ddi:iotics:iotHHHHKpPGWyEC4FFo4d6oyzVVk6MXLmEgY", // Invalid prefix
		"did:iotics:iotHHHHKpPGWyEC4FFo4d6oyzVVk6MXLmEI",  // Invalid 'I' character
		"did:iotics:iotHHHHKpPGWyEC4FFo4d6oyzVVk6MXLmEg",  // Invalid size
	}
	for _, d := range data {
		err := validation.ValidateIdentifier(d)
		assert.ErrorContains(t, err, "invalid identifier")
	}
}

func Test_valid_issuer(t *testing.T) {
	err := validation.ValidateIssuer(validDid + validName)
	assert.NilError(t, err)
}

func Test_invalid_issuer(t *testing.T) {
	data := []string{
		"",
		"hello",
	}
	for _, d := range data {
		err := validation.ValidateIssuer(d)
		assert.ErrorContains(t, err, "invalid issuer")
	}
}

func Test_valid_keyname(t *testing.T) {
	data := []string{
		"#AName",
		"#a",
		"#b-C-8",
	}
	for _, d := range data {
		err := validation.ValidateKeyName(d)
		assert.NilError(t, err)
	}
}

func Test_invalid_keyname(t *testing.T) {
	data := []string{
		"AName",                       // Invalid prefix
		"#" + strings.Repeat("a", 50), // Too long
		"#a+plop",                     // Invalid char
	}
	for _, d := range data {
		err := validation.ValidateKeyName(d)
		assert.ErrorContains(t, err, "invalid name")
	}
}
