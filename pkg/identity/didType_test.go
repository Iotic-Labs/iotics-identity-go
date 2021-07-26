// Copyright (c) IOTIC LABS LIMITED. All rights reserved. Licensed under the Apache License, Version 2.0.

package identity_test

import (
	"testing"

	"github.com/Iotic-Labs/iotics-identity-go/pkg/identity"
	"gotest.tools/assert"
)

func Test_can_parse_DidType(t *testing.T) {
	cases := []struct {
		name    string
		purpose identity.DidType
	}{
		{"host", identity.Host},
		{"user", identity.User},
		{"agent", identity.Agent},
		{"twin", identity.Twin},
	}
	for _, c := range cases {
		id, err := identity.ParseDidType(c.name)
		assert.NilError(t, err)
		assert.Check(t, id == c.purpose)
	}

	id, err := identity.ParseDidType("not_found")
	assert.Check(t, id == 0)
	assert.ErrorContains(t, err, "could not parse DidType")
}
