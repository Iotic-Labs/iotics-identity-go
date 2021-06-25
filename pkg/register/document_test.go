// Copyright (c) IOTIC LABS LIMITED. All rights reserved. Licensed under the Apache License, Version 2.0.

package register_test

import (
	"github.com/Iotic-Labs/iotics-identity-go/pkg/test"
	"testing"

	"gotest.tools/assert"
)

func Test_get_public_key_by_name(t *testing.T) {
	doc, issuer, _ := test.HelperGetRegisterDocument()
	regPub := doc.PublicKeyByName(issuer.Name)
	assert.Check(t, regPub.Name() == issuer.Name)
	assert.Check(t, regPub.PublicKeyBase58 == doc.PublicKeys[0].PublicKeyBase58)
}

func Test_get_public_key_by_name_not_found(t *testing.T) {
	doc, _, _ := test.HelperGetRegisterDocument()
	regPub := doc.PublicKeyByName("#not-found")
	assert.Check(t, regPub == nil)
}
