// Copyright (c) IOTIC LABS LIMITED. All rights reserved. Licensed under the Apache License, Version 2.0.

package main_test

import (
	"github.com/Iotic-Labs/iotics-identity-go/v3/pkg/register"
	"github.com/go-bdd/gobdd"
	"gotest.tools/assert"
)

type ctxKey int

const (
	ctxUserSeed ctxKey = iota
	ctxAgentSeed
	ctxTwinSeed
	ctxUserKeyName
	ctxAgentKeyName
	ctxTwinKeyName
	ctxUserIssuerName
	ctxAgentIssuerName
	ctxTwinIssuerName
	ctxRegisteredUser
	ctxRegisteredAgent
	ctxRegisteredTwin
	ctxDelegationName
	ctxUseLegacySeedMethod
	ctxRetrievedDoc
	ctxAllOwnersPubKeys
	ctxOtherRegisteredTwin
	ctxOtherTwinIdentityExtraOwnerKeyPair
	ctxOtherTwinIdentityExtraOwnerName
	ctxOtherTwinIdentityIssuer
	ctxOtherTwinIdentityName
	ctxOtherTwinIdentityPubKey
	ctxDelegationProof
	ctxAuthTokenDuration
	ctxTargetAudience
	ctxAuthToken
	ctxAllowedForAuth
	ctxAllowedForControl
	ctxNewOwnerKeyName
	ctxRegisteredUserDocument
	ctxRegisteredAgentDocument
	ctxRegisteredTwinDocument
)

func (c ctxKey) GetRegisteredIdentity(t gobdd.StepTest, ctx gobdd.Context) register.RegisteredIdentity {
	value, _ := ctx.Get(c)
	identity := value.(register.RegisteredIdentity)
	assert.Assert(t, identity != nil)
	return identity
}

func (c ctxKey) GetRegisteredDocument(t gobdd.StepTest, ctx gobdd.Context) *register.RegisterDocument {
	value, _ := ctx.Get(c)
	doc := value.(*register.RegisterDocument)
	assert.Assert(t, doc != nil)
	return doc
}
