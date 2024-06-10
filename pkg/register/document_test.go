// Copyright (c) IOTIC LABS LIMITED. All rights reserved. Licensed under the Apache License, Version 2.0.

package register_test

import (
	"strings"
	"testing"

	"github.com/Iotic-Labs/iotics-identity-go/v3/pkg/register"
	"github.com/Iotic-Labs/iotics-identity-go/v3/pkg/test"

	"gotest.tools/assert"
)

func Test_get_public_key_by_name(t *testing.T) {
	doc, issuer, _ := test.HelperGetRegisterDocument()
	regPub := doc.PublicKeyByID(issuer.Name)
	assert.Check(t, regPub.ID == issuer.Name)
	assert.Check(t, regPub.PublicKeyBase58 == doc.PublicKeys[0].PublicKeyBase58)
}

func Test_get_public_key_by_name_not_found(t *testing.T) {
	doc, _, _ := test.HelperGetRegisterDocument()
	regPub := doc.PublicKeyByID("#not-found")
	assert.Check(t, regPub == nil)
}

func Test_validate_context(t *testing.T) {
	doc, _, _ := test.HelperGetRegisterDocument()
	doc.Context = "bad"
	errs := doc.Validate()
	assert.Check(t, len(errs) == 1)
	assert.ErrorContains(t, errs[0], "document context must be: 'https://w3id.org/did/v1'")
}

func Test_validate_version(t *testing.T) {
	doc, _, _ := test.HelperGetRegisterDocument()
	doc.IoticsSpecVersion = "999"
	errs := doc.Validate()
	assert.Check(t, len(errs) == 1)
	assert.ErrorContains(t, errs[0], "document version should be:")
}

func Test_validate_type(t *testing.T) {
	doc, _, _ := test.HelperGetRegisterDocument()
	doc.IoticsDIDType = "bad"
	errs := doc.Validate()
	assert.Check(t, len(errs) == 1)
	assert.ErrorContains(t, errs[0], "could not parse DidType: \"bad\"")
}

func Test_validate_controller(t *testing.T) {
	doc, _, _ := test.HelperGetRegisterDocument()
	doc.Controller = doc.ID
	errs := doc.Validate()
	assert.Check(t, len(errs) == 1)
	assert.ErrorContains(t, errs[0], "document controller cannot be self")
}

func Test_validate_metadata_multiple(t *testing.T) {
	doc, _, _ := test.HelperGetRegisterDocument()
	doc.Metadata.Label = strings.Repeat("a", 65)
	doc.Metadata.Comment = strings.Repeat("a", 513)
	doc.Metadata.URL = strings.Repeat("a", 513)
	errs := doc.Validate()
	assert.Check(t, len(errs) == 3)
	assert.ErrorContains(t, errs[0], "metadata label is longer than max 64")
	assert.ErrorContains(t, errs[1], "metadata comment is longer than max 512")
	assert.ErrorContains(t, errs[2], "metadata url is longer than max 512")
}

func Test_validate_keyname_unique_multiple(t *testing.T) {
	doc, _, _ := test.HelperGetRegisterDocument()
	doc.PublicKeys = append(doc.PublicKeys, register.RegisterPublicKey{
		ID:              doc.PublicKeys[0].ID,
		Type:            register.PublicKeyTypeString,
		PublicKeyBase58: doc.PublicKeys[0].PublicKeyBase58,
		Revoked:         doc.PublicKeys[0].Revoked,
	})
	doc.AuthenticationKeys = append(doc.AuthenticationKeys, register.RegisterPublicKey{
		ID:              doc.PublicKeys[0].ID,
		Type:            register.AuthenticationKeyTypeString,
		PublicKeyBase58: doc.PublicKeys[0].PublicKeyBase58,
		Revoked:         doc.PublicKeys[0].Revoked,
	})
	errs := doc.Validate()
	assert.Check(t, len(errs) == 2)
	assert.ErrorContains(t, errs[0], "key name '#user-name' is not unique")
	assert.ErrorContains(t, errs[1], "key name '#user-name' is not unique")
}

func Test_validate_public_keys(t *testing.T) {
	doc, _, _ := test.HelperGetRegisterDocument()
	doc.PublicKeys[0].ID = "#?!&"
	doc.PublicKeys[0].Type = "bad type"
	doc.PublicKeys[0].PublicKeyBase58 = "bad key"
	errs := doc.Validate()
	assert.Check(t, len(errs) == 3)
	assert.ErrorContains(t, errs[0], "invalid name '#?!&' does not match pattern")
	assert.ErrorContains(t, errs[1], "public key ID #?!& unexpected type")
	assert.ErrorContains(t, errs[2], "public key bytes wrong length 0 != 65")
}

func Test_validate_delegation(t *testing.T) {
	doc, _, _ := test.HelperGetRegisterDocument()
	doc.DelegateControl = append(doc.DelegateControl, register.RegisterDelegationProof{
		ID:         "#$?!&",
		Controller: "bad id",
		Proof:      "not validated",
		Revoked:    false,
	})
	doc.DelegateControl = append(doc.DelegateControl, register.RegisterDelegationProof{
		ID:         "#$?!&",
		Controller: "bad id",
		Proof:      "not validated",
		Revoked:    false,
	})
	errs := doc.Validate()
	assert.Check(t, len(errs) == 5)
	assert.ErrorContains(t, errs[0], "invalid name")
	assert.ErrorContains(t, errs[1], "invalid issuer")
	assert.ErrorContains(t, errs[2], "invalid name")
	assert.ErrorContains(t, errs[3], "invalid issuer")
	assert.ErrorContains(t, errs[4], "not unique")
}

func Test_validate_no_keys(t *testing.T) {
	doc, _, _ := test.HelperGetRegisterDocument()
	doc.PublicKeys = nil
	errs := doc.Validate()
	assert.Check(t, len(errs) == 1)
	assert.ErrorContains(t, errs[0], "must have controller or one public key")
}

func TestValidateUpdateDocumentPublicKeys(t *testing.T) {
	doc, _, _ := test.HelperGetRegisterDocument()

	// Add dummy Delegation, this does not need to be valid, as the check to ensure a key
	// is not removed, does not validate the key, as that is handled elsewhere
	doc.DelegateControl = append(doc.DelegateControl, register.RegisterDelegationProof{
		ID:         "existing",
		Controller: "none",
		Proof:      "abbc",
		ProofType:  "bbca",
		Revoked:    false,
	})
	doc.DelegateAuthentication = append(doc.DelegateAuthentication, register.RegisterDelegationProof{
		ID:         "existing",
		Controller: "none",
		Proof:      "abbc",
		ProofType:  "bbca",
		Revoked:    false,
	})

	// Setup a second key and another delegation proof
	newKey := register.RegisterPublicKey{
		ID:              "fake-key",
		Type:            "fake-key",
		PublicKeyBase58: "123abc",
		Revoked:         false,
	}
	proof := register.RegisterDelegationProof{
		ID:         "1",
		Controller: "2",
		Proof:      "3",
		ProofType:  "4",
		Revoked:    false,
	}

	// Test cases
	tests := []struct {
		name      string
		newDoc    *register.RegisterDocument
		shouldErr bool
	}{
		{
			"Should be able to add new key with existing public key",
			&register.RegisterDocument{
				PublicKeys:             append(doc.PublicKeys, newKey),
				AuthenticationKeys:     doc.AuthenticationKeys,
				DelegateControl:        doc.DelegateControl,
				DelegateAuthentication: doc.DelegateAuthentication,
			},
			false,
		},
		{
			"Should not be able to add new key without existing public key",
			&register.RegisterDocument{
				PublicKeys:             []register.RegisterPublicKey{newKey},
				AuthenticationKeys:     doc.AuthenticationKeys,
				DelegateControl:        doc.DelegateControl,
				DelegateAuthentication: doc.DelegateAuthentication,
			},
			true,
		},
		{
			"Should be able to add new key with existing auth key",
			&register.RegisterDocument{
				PublicKeys:             doc.PublicKeys,
				AuthenticationKeys:     append(doc.AuthenticationKeys, newKey),
				DelegateControl:        doc.DelegateControl,
				DelegateAuthentication: doc.DelegateAuthentication,
			},
			false,
		},
		{
			"Should not be able to add new key without existing auth key",
			&register.RegisterDocument{
				PublicKeys:             doc.PublicKeys,
				AuthenticationKeys:     []register.RegisterPublicKey{newKey},
				DelegateControl:        doc.DelegateControl,
				DelegateAuthentication: doc.DelegateAuthentication,
			},
			true,
		},
		{
			"Should be able to add new key with existing delegate control",
			&register.RegisterDocument{
				PublicKeys:             doc.PublicKeys,
				AuthenticationKeys:     doc.AuthenticationKeys,
				DelegateControl:        append(doc.DelegateControl, proof),
				DelegateAuthentication: doc.DelegateAuthentication,
			},
			false,
		},
		{
			"Should not be able to add new key without existing delegate control",
			&register.RegisterDocument{
				PublicKeys:             doc.PublicKeys,
				AuthenticationKeys:     doc.AuthenticationKeys,
				DelegateControl:        []register.RegisterDelegationProof{proof},
				DelegateAuthentication: doc.DelegateAuthentication,
			},
			true,
		},
		{
			"Should be able to add new key with existing delegate auth",
			&register.RegisterDocument{
				PublicKeys:             doc.PublicKeys,
				AuthenticationKeys:     doc.AuthenticationKeys,
				DelegateControl:        doc.DelegateControl,
				DelegateAuthentication: append(doc.DelegateAuthentication, proof),
			},
			false,
		},
		{
			"Should not be able to add new key without existing delegate auth",
			&register.RegisterDocument{
				PublicKeys:             doc.PublicKeys,
				AuthenticationKeys:     doc.AuthenticationKeys,
				DelegateControl:        doc.DelegateControl,
				DelegateAuthentication: []register.RegisterDelegationProof{proof},
			},
			true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := doc.ValidateUpdateDocument(tt.newDoc)
			if err != nil && !tt.shouldErr {
				// Error occurred when it shouldn't have
				t.Errorf("ValidateUpdateDocument() error occurred = %v", err)
			} else if err != nil && tt.shouldErr {
				// It errors, and it should, check the error
				assert.ErrorContains(t, err, "cannot be removed, only revoked")
			} else if err == nil && tt.shouldErr {
				// There is no error, but there should be
				t.Error("ValidateUpdateDocument() expected error")
			}
		})
	}
}
