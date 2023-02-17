// Copyright (c) IOTIC LABS LIMITED. All rights reserved. Licensed under the Apache License, Version 2.0.

package register_test

import (
	"context"
	"testing"

	"github.com/Iotic-Labs/iotics-identity-go/v2/pkg/test"

	"github.com/Iotic-Labs/iotics-identity-go/v2/pkg/register"
	"gotest.tools/assert"
)

func Test_can_get_issuer_from_public_keys(t *testing.T) {
	name := "#user-name"
	doc, _, _ := test.HelperGetRegisterDocument()
	issuer, err := register.GetIssuerRegisterKey(name, doc, false)
	assert.NilError(t, err)
	assert.Assert(t, issuer.ID == name)
	assert.Assert(t, issuer.PublicKeyBase58 == test.ValidKeyPair.PublicKeyBase58)
}

func Test_get_issuer_from_public_keys_returns_none_if_not_found(t *testing.T) {
	name := "#not-found"
	doc, _, _ := test.HelperGetRegisterDocument()
	issuer, err := register.GetIssuerRegisterKey(name, doc, false)
	assert.ErrorContains(t, err, "issuer key not found")
	assert.Assert(t, issuer == nil)
}

func Test_can_get_issuer_from_auth_keys(t *testing.T) {
	name := "#name2"
	doc, _, _ := test.HelperGetRegisterDocument()
	issuer, err := register.GetIssuerRegisterKey(name, doc, true)
	assert.NilError(t, err)
	assert.Assert(t, issuer.ID == name)
	assert.Assert(t, issuer.PublicKeyBase58 == test.ValidKeyPair2.PublicKeyBase58)
}

func Test_get_issuer_from_auth_keys_returns_none_if_not_found(t *testing.T) {
	name := "#not-found"
	doc, _, _ := test.HelperGetRegisterDocument()
	issuer, err := register.GetIssuerRegisterKey(name, doc, true)
	assert.ErrorContains(t, err, "issuer key not found")
	assert.Assert(t, issuer == nil)
}

func Test_get_issuer_from_auth_keys_returns_none_if_in_auth_keys_but_auth_not_included(t *testing.T) {
	name := "#name2"
	doc, _, _ := test.HelperGetRegisterDocument()
	issuer, err := register.GetIssuerRegisterKey(name, doc, false)
	assert.ErrorContains(t, err, "issuer key not found")
	assert.Assert(t, issuer == nil)
}

func Test_can_get_issuer_from_control_delegation(t *testing.T) {
	resolver := test.NewInMemoryResolver()
	userIdentity, _ := test.SetupIdentitiesForAuth(resolver, true, false)

	userDoc, _ := resolver.GetDocument(context.TODO(), userIdentity.Did())

	issuer, err := register.GetIssuerRegisterDelegationProof("#delegCtrl", userDoc, false)
	assert.NilError(t, err)
	assert.Assert(t, issuer.ID == "#delegCtrl")
}

func Test_get_issuer_from_control_delegation_returns_none_if_not_found(t *testing.T) {
	resolver := test.NewInMemoryResolver()
	userIdentity, _ := test.SetupIdentitiesForAuth(resolver, false, false)

	userDoc, _ := resolver.GetDocument(context.TODO(), userIdentity.Did())

	issuer, err := register.GetIssuerRegisterDelegationProof("#delegCtrl", userDoc, false)
	assert.ErrorContains(t, err, "delegation now found for issuer")
	assert.Assert(t, issuer == nil)
}

func Test_can_get_issuer_from_auth_delegation(t *testing.T) {
	resolver := test.NewInMemoryResolver()
	userIdentity, _ := test.SetupIdentitiesForAuth(resolver, false, true)

	userDoc, _ := resolver.GetDocument(context.TODO(), userIdentity.Did())

	issuer, err := register.GetIssuerRegisterDelegationProof("#delegAuth", userDoc, true)
	assert.NilError(t, err)
	assert.Assert(t, issuer.ID == "#delegAuth")
}

func Test_get_issuer_from_auth_delegation_returns_none_if_not_found(t *testing.T) {
	resolver := test.NewInMemoryResolver()
	userIdentity, _ := test.SetupIdentitiesForAuth(resolver, false, false)

	userDoc, _ := resolver.GetDocument(context.TODO(), userIdentity.Did())

	issuer, err := register.GetIssuerRegisterDelegationProof("#delegAuth", userDoc, true)
	assert.ErrorContains(t, err, "delegation now found for issuer")
	assert.Assert(t, issuer == nil)
}

func Test_get_issuer_from_auth_delegation_returns_none_if_in_auth_keys_but_auth_not_included(t *testing.T) {
	resolver := test.NewInMemoryResolver()
	userIdentity, _ := test.SetupIdentitiesForAuth(resolver, false, true)

	userDoc, _ := resolver.GetDocument(context.TODO(), userIdentity.Did())

	issuer, err := register.GetIssuerRegisterDelegationProof("#delegAuth", userDoc, false)
	assert.ErrorContains(t, err, "delegation now found for issuer")
	assert.Assert(t, issuer == nil)
}

func Test_can_get_control_delegation_by_controller(t *testing.T) {
	// TODO:
	t.Skip()
}

func Test_get_control_delegation_by_controller_returns_none_if_not_found(t *testing.T) {
	// TODO:
	t.Skip()
}

func Test_can_get_auth_delegation_by_controller(t *testing.T) {
	// TODO:
	t.Skip()
}

func Test_get_auth_delegation_by_controller_returns_none_if_not_found(t *testing.T) {
	// TODO:
	t.Skip()
}

func Test_can_get_valid_issuer_for_control_only(t *testing.T) {
	// TODO:
	t.Skip()
}

func Test_can_get_valid_issuer_for_auth(t *testing.T) {
	// TODO:
	t.Skip()
}

func Test_get_valid_issuer_for_control_only_returns_none_if_not_found(t *testing.T) {
	// TODO:
	t.Skip()
}

func Test_get_valid_issuer_for_auth_returns_none_if_not_found(t *testing.T) {
	// TODO:
	t.Skip()
}

func Test_can_get_owner_public_key(t *testing.T) {
	resolver := test.NewInMemoryResolver()
	userIdentity, _ := test.SetupIdentitiesForAuth(resolver, false, true)

	userDoc, _ := resolver.GetDocument(context.TODO(), userIdentity.Did())

	issuer, err := register.GetOwnerRegisterPublicKey(userDoc)
	assert.NilError(t, err)
	assert.Check(t, issuer.ID == "#user")
}

func Test_get_owner_public_key_returns_none_if_not_found(t *testing.T) {
	// TODO:
	t.Skip()
}

func Test_can_get_issuer_by_public_key(t *testing.T) {
	// TODO:
	t.Skip()
}

func Test_get_issuer_by_public_key_returns_none_if_not_found(t *testing.T) {
	// TODO:
	t.Skip()
}
