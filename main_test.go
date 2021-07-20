// Copyright (c) IOTIC LABS LIMITED. All rights reserved. Licensed under the Apache License, Version 2.0.

package main_test

import (
	"encoding/hex"
	"fmt"
	"testing"
	"time"

	"github.com/Iotic-Labs/iotics-identity-go/pkg/advancedapi"
	"github.com/Iotic-Labs/iotics-identity-go/pkg/api"
	"github.com/Iotic-Labs/iotics-identity-go/pkg/crypto"
	"github.com/Iotic-Labs/iotics-identity-go/pkg/identity"
	"github.com/Iotic-Labs/iotics-identity-go/pkg/proof"
	"github.com/Iotic-Labs/iotics-identity-go/pkg/register"
	"github.com/Iotic-Labs/iotics-identity-go/pkg/test"
	"gotest.tools/assert"

	"github.com/go-bdd/gobdd"
)

var (
	testSeed, _ = hex.DecodeString("8e083334168ead990327d871d58d696aeb9f056a6fd7caddaed02d7d218cff51")
)

var resolver *test.InMemoryResolver

func aResolverExists(t gobdd.StepTest, ctx gobdd.Context) {
	resolver = test.NewInMemoryResolver()
}

func userSeed(t gobdd.StepTest, ctx gobdd.Context, value string) {
	ctx.Set(ctxUserSeed, value)
}

func userKeyName(t gobdd.StepTest, ctx gobdd.Context, value string) {
	ctx.Set(ctxUserKeyName, value)
}

func userIssuerName(t gobdd.StepTest, ctx gobdd.Context, value string) {
	ctx.Set(ctxUserIssuerName, value)
}

func agentSeed(t gobdd.StepTest, ctx gobdd.Context, value string) {
	ctx.Set(ctxAgentSeed, value)
}

func agentKeyName(t gobdd.StepTest, ctx gobdd.Context, value string) {
	ctx.Set(ctxAgentKeyName, value)
}

func agentIssuerName(t gobdd.StepTest, ctx gobdd.Context, value string) {
	ctx.Set(ctxAgentIssuerName, value)
}

func twinSeed(t gobdd.StepTest, ctx gobdd.Context, value string) {
	ctx.Set(ctxTwinSeed, value)
}

func twinKeyName(t gobdd.StepTest, ctx gobdd.Context, value string) {
	ctx.Set(ctxTwinKeyName, value)
}

func twinIssuerName(t gobdd.StepTest, ctx gobdd.Context, value string) {
	ctx.Set(ctxTwinIssuerName, value)
}

func aNewOwnerKeyNameIs(t gobdd.StepTest, ctx gobdd.Context, value string) {
	ctx.Set(ctxNewOwnerKeyName, value)
}

func theLegacySeedMethod(t gobdd.StepTest, ctx gobdd.Context) {
	ctx.Set(ctxUseLegacySeedMethod, "legacy")
}

// TODO: remove - shouldn't be in use
func anExistingRegisteredEntityType(t gobdd.StepTest, ctx gobdd.Context, entityType string) {
	//name := "#RegisteredExisting" + entityType
	switch entityType {
	case "agent":
		ctx.Set(ctxAgentKeyName, "#KeyAgent1")
	case "twin":
		ctx.Set(ctxTwinKeyName, "#KeyTwin1")
	case "user":
		// DID Type User
		// Create
		ctx.Set(ctxUserKeyName, "#KeyUser1")
	}
}

func aDelegationName(t gobdd.StepTest, ctx gobdd.Context, value string) {
	ctx.Set(ctxDelegationName, value)
}

func aRegisteredUser(t gobdd.StepTest, ctx gobdd.Context) {
	seed, _ := crypto.CreateSeed(128)
	opts := &api.CreateIdentityOpts{
		Seed:    seed,
		KeyName: "RegUserKey1",
	}
	user, _ := api.CreateUserIdentity(resolver, opts)
	ctx.Set(ctxRegisteredUser, user)
}

func aRegisteredAgent(t gobdd.StepTest, ctx gobdd.Context) {
	seed, _ := crypto.CreateSeed(128)
	opts := &api.CreateIdentityOpts{
		Seed:    seed,
		KeyName: "RegAgentKey1",
	}
	agent, _ := api.CreateAgentIdentity(resolver, opts)
	ctx.Set(ctxRegisteredAgent, agent)
}

func aRegisteredTwin(t gobdd.StepTest, ctx gobdd.Context) {
	seed, _ := crypto.CreateSeed(128)
	opts := &api.CreateIdentityOpts{
		Seed:    seed,
		KeyName: "RegTwinKey1",
	}
	twin, _ := api.CreateTwinIdentity(resolver, opts)
	ctx.Set(ctxRegisteredTwin, twin)
}

func registerTwinIdentity(t gobdd.StepTest, name string) register.RegisteredIdentity {
	keyPair := getNewKeyPair(name)
	registeredTwin, err := advancedapi.NewRegisteredIdentity(resolver, identity.Twin, keyPair, name, false)
	assert.NilError(t, err)
	return registeredTwin
}

// TODO: get the twin key name from ctx.GetString(ctxTwinKeyName) instead
// and add an extra step accordingly to the feature file
func aRegisteredIdentityWithName(t gobdd.StepTest, ctx gobdd.Context, name string) {
	ctx.Set(ctxTwinKeyName, name)
	ctx.Set(ctxRegisteredTwin, registerTwinIdentity(t, name))
}

func aAnotherRegisteredIdentityWithName(t gobdd.StepTest, ctx gobdd.Context, name string) {
	ctx.Set(ctxOtherRegisteredTwin, registerTwinIdentity(t, name))
}

func aRegisteredIdentityOwningTheDocument(t gobdd.StepTest, ctx gobdd.Context) {}

func getNewKeyPair(name string) *crypto.KeyPair {
	path := crypto.PathForDIDType(name, identity.Twin)
	secret, _ := crypto.NewDefaultKeyPairSecrets(testSeed, path)
	keyPair, _ := crypto.GetKeyPair(secret)
	return keyPair
}

func aRegisterDocumentWithSeveralOwners(t gobdd.StepTest, ctx gobdd.Context) {
	name := "#Owner1"
	keyPair := getNewKeyPair(name)
	o2name := "#Owner2"
	o2publicKeyBase58 := getNewKeyPair(o2name).PublicKeyBase58
	o3name := "#Owner3"
	o3publicKeyBase58 := getNewKeyPair(o3name).PublicKeyBase58

	registeredTwin, _ := advancedapi.NewRegisteredIdentity(resolver, identity.Twin, keyPair, name, false)
	api.AddNewOwner(resolver, o2name, o2publicKeyBase58, registeredTwin)
	api.AddNewOwner(resolver, o3name, o3publicKeyBase58, registeredTwin)

	ctx.Set(ctxAllOwnersPubKeys, []string{keyPair.PublicKeyBase58, o2publicKeyBase58, o3publicKeyBase58})
	ctx.Set(ctxTwinKeyName, name)
	ctx.Set(ctxRegisteredTwin, registeredTwin)
}

func aNewTwinNameAndPublicKey(t gobdd.StepTest, ctx gobdd.Context, name string) {
	keyPair := getNewKeyPair(name)
	ctx.Set(ctxOtherTwinIdentityName, name)
	ctx.Set(ctxOtherTwinIdentityPubKey, keyPair.PublicKeyBase58)
}

func aAnotherTwinOwner(t gobdd.StepTest, ctx gobdd.Context, name string) {
	keyPair := getNewKeyPair(name)
	registeredTwin, _ := ctx.Get(ctxRegisteredTwin)
	assert.Assert(t, registeredTwin != nil)
	api.AddNewOwner(resolver, name, keyPair.PublicKeyBase58, registeredTwin.(register.RegisteredIdentity))
	ctx.Set(ctxOtherTwinIdentityName, name)
	ctx.Set(ctxOtherTwinIdentityPubKey, keyPair.PublicKeyBase58)
}

func aAnotherTwinAuthenticationPublicKey(t gobdd.StepTest, ctx gobdd.Context, name string) {
	keyPair := getNewKeyPair(name)
	registeredTwin, _ := ctx.Get(ctxRegisteredTwin)
	assert.Assert(t, registeredTwin != nil)
	err := advancedapi.AddAuthenticationKeyToDocument(resolver, name, keyPair.PublicKeyBase58, registeredTwin.(register.RegisteredIdentity))
	assert.NilError(t, err)
	ctx.Set(ctxOtherTwinIdentityName, name)
	ctx.Set(ctxOtherTwinIdentityPubKey, keyPair.PublicKeyBase58)
}

func aDelegationProofCreatedForBy(t gobdd.StepTest, ctx gobdd.Context, createdForName string, createdByName string) {
	registeredTwin, _ := ctx.Get(ctxRegisteredTwin)
	assert.Assert(t, registeredTwin != nil)
	initialIdentity := registeredTwin.(register.RegisteredIdentity)
	otherRegisteredTwin, _ := ctx.Get(ctxOtherRegisteredTwin)
	assert.Assert(t, otherRegisteredTwin != nil)
	otherIdentity := otherRegisteredTwin.(register.RegisteredIdentity)
	doc, err := advancedapi.GetRegisterDocument(resolver, otherIdentity.Did())
	assert.NilError(t, err)
	issuer, pr, err := advancedapi.CreateDelegationProof(initialIdentity.Issuer(), doc, otherIdentity.KeyPair())
	assert.NilError(t, err)
	assert.DeepEqual(t, issuer, otherIdentity.Issuer())
	ctx.Set(ctxDelegationProof, pr)
}

func aRegisterIdentityIDAOwningTheDocumentDocAWithAnAuthDelegationProofCreatedByADelegatedRegisteredIdentity(t gobdd.StepTest, ctx gobdd.Context) {
}
func aRegisterIdentityIDAOwningTheDocumentDocAAndAControllerRegisteredIdentity(t gobdd.StepTest, ctx gobdd.Context) {
}

func aAnotherRegisteredIdentityWithNameAndAnExtraOwner(t gobdd.StepTest, ctx gobdd.Context, identityName string, extraOwnerName string) {
	otherIdentity := registerTwinIdentity(t, identityName)
	extraOwnerKeyPair := getNewKeyPair(extraOwnerName)
	api.AddNewOwner(resolver, extraOwnerName, extraOwnerKeyPair.PublicKeyBase58, otherIdentity)
	ctx.Set(ctxOtherRegisteredTwin, otherIdentity)
	ctx.Set(ctxOtherTwinIdentityExtraOwnerName, extraOwnerName)
	ctx.Set(ctxOtherTwinIdentityExtraOwnerKeyPair, extraOwnerKeyPair)
}

func aRegisterIdentityIDAOwningTheDocumentDocAWithAControlDelegationProofCreatedByADelegatedRegisteredIdentityWithSeveralOwner(t gobdd.StepTest, ctx gobdd.Context) {
}
func aIdentityTypeSeedAndAIdentityTypeKeyNameFromARegisteredIdentity(t gobdd.StepTest, ctx gobdd.Context, identityType string, keyName string) {
}
func aControllerIssuer(t gobdd.StepTest, ctx gobdd.Context)                                      {}
func aCreator(t gobdd.StepTest, ctx gobdd.Context)                                               {}
func aNotRevokedRegisteredIdentity(t gobdd.StepTest, ctx gobdd.Context)                          {}
func anExistingRegisteredIdentity(t gobdd.StepTest, ctx gobdd.Context)                           {}
func anExistingRegisteredDocument(t gobdd.StepTest, ctx gobdd.Context)                           {}
func aCorruptedRegisteredDocument(t gobdd.StepTest, ctx gobdd.Context)                           {}
func aRegisterUserDocument(t gobdd.StepTest, ctx gobdd.Context)                                  {}
func aRegisterAgentDocument(t gobdd.StepTest, ctx gobdd.Context, withOrWithoutDelegation string) {}
func aNewOwnerKeyNameAnRegisteredIdentityRegister(t gobdd.StepTest, ctx gobdd.Context)           {}
func aOwnerKeyNameAnRegisteredIdentityRegister(t gobdd.StepTest, ctx gobdd.Context)              {}

func theAuthTokenDurationIs(t gobdd.StepTest, ctx gobdd.Context, duration string) {
	ctx.Set(ctxAuthTokenDuration, duration)
}
func theTargetAudienceIs(t gobdd.StepTest, ctx gobdd.Context, audience string) {
	ctx.Set(ctxTargetAudience, audience)
}

// When
func iCreateUserAndAgentWithAuthenticationDelegation(t gobdd.StepTest, ctx gobdd.Context) {
	userSeedValue, _ := ctx.GetString(ctxUserSeed)
	userSeed, _ := hex.DecodeString(userSeedValue)
	userKeyName, _ := ctx.GetString(ctxUserKeyName)
	agentSeedValue, _ := ctx.GetString(ctxAgentSeed)
	agentSeed, _ := hex.DecodeString(agentSeedValue)
	agentKeyName, _ := ctx.GetString(ctxAgentKeyName)
	delegationName, _ := ctx.GetString(ctxDelegationName)
	opts := &api.CreateUserAndAgentWithAuthDelegationOpts{
		UserSeed:       userSeed,
		UserKeyName:    userKeyName,
		UserName:       "",
		UserPassword:   "",
		AgentSeed:      agentSeed,
		AgentKeyName:   agentKeyName,
		AgentName:      "",
		AgentPassword:  "",
		DelegationName: delegationName,
		OverrideDocs:   false,
	}
	userId, agentId, err := api.CreateUserAndAgentWithAuthDelegation(resolver, opts)
	assert.NilError(t, err)
	ctx.Set(ctxRegisteredUser, userId)
	ctx.Set(ctxRegisteredAgent, agentId)
}

func iCreateAUser(t gobdd.StepTest, ctx gobdd.Context) {
	userSeedValue, _ := ctx.GetString(ctxUserSeed)
	userSeed, _ := hex.DecodeString(userSeedValue)
	userKeyName, _ := ctx.GetString(ctxUserKeyName)
	opts := &api.CreateIdentityOpts{
		Seed:    userSeed,
		KeyName: userKeyName,
	}
	user, err := api.CreateUserIdentity(resolver, opts)
	assert.NilError(t, err)
	ctx.Set(ctxRegisteredUser, user)
}

func iCreateAnAgent(t gobdd.StepTest, ctx gobdd.Context) {
	agentSeedValue, _ := ctx.GetString(ctxAgentSeed)
	agentSeed, _ := hex.DecodeString(agentSeedValue)
	agentKeyName, _ := ctx.GetString(ctxAgentKeyName)
	opts := &api.CreateIdentityOpts{
		Seed:    agentSeed,
		KeyName: agentKeyName,
	}
	agent, err := api.CreateAgentIdentity(resolver, opts)
	assert.NilError(t, err)
	ctx.Set(ctxRegisteredAgent, agent)
}

func iCreateATwin(t gobdd.StepTest, ctx gobdd.Context) {
	twinSeedValue, _ := ctx.GetString(ctxTwinSeed)
	twinSeed, _ := hex.DecodeString(twinSeedValue)
	twinKeyName, _ := ctx.GetString(ctxTwinKeyName)
	twinIssuerName, _ := ctx.GetString(ctxTwinIssuerName)
	opts := &api.CreateIdentityOpts{
		Seed:    twinSeed,
		KeyName: twinKeyName,
		Name:    twinIssuerName,
	}

	twin, err := api.CreateTwinIdentity(resolver, opts)
	assert.NilError(t, err)
	ctx.Set(ctxRegisteredTwin, twin)
}

func iDelegateControl(t gobdd.StepTest, ctx gobdd.Context) {
	delegationName, _ := ctx.GetString(ctxDelegationName)
	agent := ctxRegisteredAgent.GetRegisteredIdentity(t, ctx)
	twin := ctxRegisteredTwin.GetRegisteredIdentity(t, ctx)
	err := api.DelegateControl(resolver, twin, agent, delegationName)
	assert.NilError(t, err)
}

func iCreateAnAgentAuthToken(t gobdd.StepTest, ctx gobdd.Context) {
	user := ctxRegisteredUser.GetRegisteredIdentity(t, ctx)
	agent := ctxRegisteredAgent.GetRegisteredIdentity(t, ctx)
	durationString, _ := ctx.GetString(ctxAuthTokenDuration)
	audience, _ := ctx.GetString(ctxTargetAudience)
	duration, _ := time.ParseDuration(durationString)
	token, err := api.CreateAgentAuthToken(agent, user.Did(), duration, audience)
	assert.NilError(t, err)
	ctx.Set(ctxAuthToken, string(token))
}

func theUserTakesOwnershipOfTheRegisteredTwin(t gobdd.StepTest, ctx gobdd.Context) {
	user := ctxRegisteredUser.GetRegisteredIdentity(t, ctx)
	twin := ctxRegisteredTwin.GetRegisteredIdentity(t, ctx)
	newOwnerKeyName, _ := ctx.GetString(ctxNewOwnerKeyName)
	err := api.GetOwnershipOfTwinFromRegisteredIdentity(resolver, twin, user, newOwnerKeyName)
	assert.NilError(t, err)
}

func iGetTheAssociatedDocument(t gobdd.StepTest, ctx gobdd.Context) {
	twin := ctxRegisteredTwin.GetRegisteredIdentity(t, ctx)
	registerDoc, err := advancedapi.GetRegisterDocument(resolver, twin.Did())

	assert.NilError(t, err)
	ctx.Set(ctxRetrievedDoc, registerDoc)
}

func iCheckIfTheRegisteredIdentityIsAllowedForControlAndAuthenticationOnTheAssociatedDocument(t gobdd.StepTest, ctx gobdd.Context) {
	registeredTwin, _ := ctx.Get(ctxRegisteredTwin)
	assert.Assert(t, registeredTwin != nil)
	initialIdentity := registeredTwin.(register.RegisteredIdentity)
	err := register.ValidateAllowedForAuth(resolver, initialIdentity.Issuer(), initialIdentity.Did())
	ctx.Set(ctxAllowedForAuth, err == nil)
	err = register.ValidateAllowedForControl(resolver, initialIdentity.Issuer(), initialIdentity.Did())
	ctx.Set(ctxAllowedForControl, err == nil)

}

func iAddTheNewOwnerToTheDocument(t gobdd.StepTest, ctx gobdd.Context) {
	name, _ := ctx.GetString(ctxOtherTwinIdentityName)
	publicKeyBase58, _ := ctx.GetString(ctxOtherTwinIdentityPubKey)
	registeredTwin, _ := ctx.Get(ctxRegisteredTwin)
	advancedapi.AddPublicKeyToDocument(resolver, name, publicKeyBase58, registeredTwin.(register.RegisteredIdentity))
}

func iRemoveTheOtherOwnerFromTheDocument(t gobdd.StepTest, ctx gobdd.Context) {
	nameToRemove, _ := ctx.GetString(ctxOtherTwinIdentityName)
	publicKeyBase58ToRemove, _ := ctx.GetString(ctxOtherTwinIdentityPubKey)
	registeredTwin, _ := ctx.Get(ctxRegisteredTwin)
	initialOwner := registeredTwin.(register.RegisteredIdentity)

	doc, err := advancedapi.GetRegisterDocument(resolver, initialOwner.Did())
	assert.NilError(t, err)
	otherIssuer, err := advancedapi.GetIssuerByPublicKey(doc, publicKeyBase58ToRemove)
	assert.NilError(t, err)

	advancedapi.RemovePublicKeyFromDocument(resolver, nameToRemove, initialOwner)
	ctx.Set(ctxOtherTwinIdentityIssuer, otherIssuer)
}

func iRevokeTheOtherOwnerKey(t gobdd.StepTest, ctx gobdd.Context) {
	nameToRevoke, _ := ctx.GetString(ctxOtherTwinIdentityName)
	publicKeyBase58ToRevoke, _ := ctx.GetString(ctxOtherTwinIdentityPubKey)
	registeredTwin, _ := ctx.Get(ctxRegisteredTwin)
	initialOwner := registeredTwin.(register.RegisteredIdentity)

	doc, err := advancedapi.GetRegisterDocument(resolver, initialOwner.Did())
	assert.NilError(t, err)
	otherIssuer, err := advancedapi.GetIssuerByPublicKey(doc, publicKeyBase58ToRevoke)
	assert.NilError(t, err)

	advancedapi.RevokePublicKeyFromDocument(resolver, nameToRevoke, initialOwner)
	ctx.Set(ctxOtherTwinIdentityIssuer, otherIssuer)
}

func iAddTheNewAuthenticationKeyToTheDocument(t gobdd.StepTest, ctx gobdd.Context) {
	name, _ := ctx.GetString(ctxOtherTwinIdentityName)
	publicKeyBase58, _ := ctx.GetString(ctxOtherTwinIdentityPubKey)
	twin := ctxRegisteredTwin.GetRegisteredIdentity(t, ctx)
	err := advancedapi.AddAuthenticationKeyToDocument(resolver, name, publicKeyBase58, twin)
	assert.NilError(t, err)
}

func iRemoveTheAuthenticationKeyFromTheDocument(t gobdd.StepTest, ctx gobdd.Context) {
	nameToRemove, _ := ctx.GetString(ctxOtherTwinIdentityName)
	initialOwner := ctxRegisteredTwin.GetRegisteredIdentity(t, ctx)
	err := advancedapi.RemovePublicKeyFromDocument(resolver, nameToRemove, initialOwner)
	assert.NilError(t, err)
}

func iRevokeTheAuthenticationKeyFromTheDocument(t gobdd.StepTest, ctx gobdd.Context) {
	nameToRevoke, _ := ctx.GetString(ctxOtherTwinIdentityName)
	initialOwner := ctxRegisteredTwin.GetRegisteredIdentity(t, ctx)
	err := advancedapi.RevokePublicKeyFromDocument(resolver, nameToRevoke, initialOwner)
	assert.NilError(t, err)
}

func iDADelegatesControlToIDB(t gobdd.StepTest, ctx gobdd.Context, name string) {
	registeredTwin, _ := ctx.Get(ctxRegisteredTwin)
	delegatingIdentity := registeredTwin.(register.RegisteredIdentity)
	subjectRegisteredTwin, _ := ctx.Get(ctxOtherRegisteredTwin)
	subjectIdentity := subjectRegisteredTwin.(register.RegisteredIdentity)
	advancedapi.DelegateControl(
		resolver, delegatingIdentity.KeyPair(), delegatingIdentity.Did(), subjectIdentity.KeyPair(), subjectIdentity.Did(), name)
	ctx.Set(ctxDelegationName, name)
}

func iDADelegatesControlToIDBWithExtraOwner(t gobdd.StepTest, ctx gobdd.Context, delegationName string) {
	registeredTwin, _ := ctx.Get(ctxRegisteredTwin)
	assert.Assert(t, registeredTwin != nil)
	initialIdentity := registeredTwin.(register.RegisteredIdentity)
	otherRegisteredTwin, _ := ctx.Get(ctxOtherRegisteredTwin)
	assert.Assert(t, otherRegisteredTwin != nil)
	otherIdentity := otherRegisteredTwin.(register.RegisteredIdentity)
	extraOwnerKeyPair, _ := ctx.Get(ctxOtherTwinIdentityExtraOwnerKeyPair)
	assert.Assert(t, extraOwnerKeyPair != nil)
	advancedapi.DelegateControl(
		resolver, initialIdentity.KeyPair(), initialIdentity.Did(), extraOwnerKeyPair.(*crypto.KeyPair), otherIdentity.Did(), delegationName)
	ctx.Set(ctxDelegationName, delegationName)
}

func iAddTheControlDelegationProofToTheDocument(t gobdd.StepTest, ctx gobdd.Context, delegationProofName string) {
	otherIdentity := ctxOtherRegisteredTwin.GetRegisteredIdentity(t, ctx)
	initialIdentity := ctxRegisteredTwin.GetRegisteredIdentity(t, ctx)

	delegationProof, _ := ctx.Get(ctxDelegationProof)
	assert.Assert(t, delegationProof != nil)
	pr := delegationProof.(*proof.Proof)

	advancedapi.AddControlDelegationToDocument(
		resolver, delegationProofName, otherIdentity.Issuer().String(), pr.Signature, initialIdentity)
	ctx.Set(ctxDelegationName, delegationProofName)
}

func iRemoveTheControlDelegationProofFromTheDocument(t gobdd.StepTest, ctx gobdd.Context) {
	delegationName, _ := ctx.GetString(ctxDelegationName)
	initialIdentity := ctxRegisteredTwin.GetRegisteredIdentity(t, ctx)
	advancedapi.RemoveControlDelegationFromDocument(resolver, delegationName, initialIdentity)
}

func iRevokeTheControlDelegationProof(t gobdd.StepTest, ctx gobdd.Context) {
	delegationName, _ := ctx.GetString(ctxDelegationName)
	initialIdentity := ctxRegisteredTwin.GetRegisteredIdentity(t, ctx)
	advancedapi.RevokeControlDelegationFromDocument(resolver, delegationName, initialIdentity)
}

func iDADelegatesAuthenticationToIDB(t gobdd.StepTest, ctx gobdd.Context, delegationName string) {
	initialIdentity := ctxRegisteredTwin.GetRegisteredIdentity(t, ctx)
	otherIdentity := ctxOtherRegisteredTwin.GetRegisteredIdentity(t, ctx)
	advancedapi.DelegateAuthentication(
		resolver, initialIdentity.KeyPair(), initialIdentity.Did(), otherIdentity.KeyPair(), otherIdentity.Did(), delegationName)
	ctx.Set(ctxDelegationName, delegationName)
}

func iDADelegatesAuthenticationToIDBWithExtraOwner(t gobdd.StepTest, ctx gobdd.Context, delegationName string) {
	registeredTwin, _ := ctx.Get(ctxRegisteredTwin)
	assert.Assert(t, registeredTwin != nil)
	initialIdentity := registeredTwin.(register.RegisteredIdentity)
	otherRegisteredTwin, _ := ctx.Get(ctxOtherRegisteredTwin)
	assert.Assert(t, otherRegisteredTwin != nil)
	otherIdentity := otherRegisteredTwin.(register.RegisteredIdentity)
	extraOwnerKeyPair, _ := ctx.Get(ctxOtherTwinIdentityExtraOwnerKeyPair)
	assert.Assert(t, extraOwnerKeyPair != nil)
	advancedapi.DelegateAuthentication(
		resolver, initialIdentity.KeyPair(), initialIdentity.Did(), extraOwnerKeyPair.(*crypto.KeyPair), otherIdentity.Did(), delegationName)
	ctx.Set(ctxDelegationName, delegationName)
}

func iAddTheAuthenticationDelegationProofToTheDocument(t gobdd.StepTest, ctx gobdd.Context, delegationProofName string) {
	otherRegisteredTwin, _ := ctx.Get(ctxOtherRegisteredTwin)
	assert.Assert(t, otherRegisteredTwin != nil)
	otherIdentity := otherRegisteredTwin.(register.RegisteredIdentity)
	delegationProof, _ := ctx.Get(ctxDelegationProof)
	assert.Assert(t, delegationProof != nil)
	pr := delegationProof.(*proof.Proof)
	registeredTwin, _ := ctx.Get(ctxRegisteredTwin)
	assert.Assert(t, registeredTwin != nil)
	initialIdentity := registeredTwin.(register.RegisteredIdentity)

	advancedapi.AddAuthenticationDelegationToDocument(
		resolver, delegationProofName, otherIdentity.Issuer().String(), pr.Signature, initialIdentity)
	ctx.Set(ctxDelegationName, delegationProofName)
}

func iRemoveTheAuthenticationDelegationProofFromTheDocument(t gobdd.StepTest, ctx gobdd.Context) {
	delegationName, _ := ctx.GetString(ctxDelegationName)
	initialIdentity := ctxRegisteredTwin.GetRegisteredIdentity(t, ctx)
	advancedapi.RemoveAuthenticationDelegationFromDocument(resolver, delegationName, initialIdentity)
}

func iRevokeTheAuthenticationDelegationProof(t gobdd.StepTest, ctx gobdd.Context) {
	delegationName, _ := ctx.GetString(ctxDelegationName)
	initialIdentity := ctxRegisteredTwin.GetRegisteredIdentity(t, ctx)
	advancedapi.RevokeAuthenticationDelegationFromDocument(resolver, delegationName, initialIdentity)
}

func iSetTheControllerOnMyDocument(t gobdd.StepTest, ctx gobdd.Context) {
	registeredTwin, _ := ctx.Get(ctxRegisteredTwin)
	assert.Assert(t, registeredTwin != nil)
	initialIdentity := registeredTwin.(register.RegisteredIdentity)
	otherRegisteredTwin, _ := ctx.Get(ctxOtherRegisteredTwin)
	assert.Assert(t, otherRegisteredTwin != nil)
	otherIdentity := otherRegisteredTwin.(register.RegisteredIdentity)
	advancedapi.SetDocumentController(resolver, initialIdentity, otherIdentity.Issuer())
}

func theDelegatedIdentityOwnerUsedForTheProofIsRevoked(t gobdd.StepTest, ctx gobdd.Context) {
	extraOwnerName, _ := ctx.GetString(ctxOtherTwinIdentityExtraOwnerName)
	assert.Assert(t, extraOwnerName != "")
	otherRegisteredTwin, _ := ctx.Get(ctxOtherRegisteredTwin)
	otherIdentity := otherRegisteredTwin.(register.RegisteredIdentity)
	advancedapi.RevokePublicKeyFromDocument(resolver, extraOwnerName, otherIdentity)
}

func theDelegatedIdentityOwnerUsedForTheProofIsRemoved(t gobdd.StepTest, ctx gobdd.Context) {
	extraOwnerName, _ := ctx.GetString(ctxOtherTwinIdentityExtraOwnerName)
	assert.Assert(t, extraOwnerName != "")
	otherRegisteredTwin, _ := ctx.Get(ctxOtherRegisteredTwin)
	otherIdentity := otherRegisteredTwin.(register.RegisteredIdentity)
	advancedapi.RemovePublicKeyFromDocument(resolver, extraOwnerName, otherIdentity)
}

func iCreateTheIdentityOverridingTheDocumentWithANewName(t gobdd.StepTest, ctx gobdd.Context, identityType string) {
}
func iGetTheIdentity(t gobdd.StepTest, ctx gobdd.Context, identityType string) {}
func userDelegatesAuthenticationToAgent(t gobdd.StepTest, ctx gobdd.Context)   {}
func twinDelegatesControlToAgent(t gobdd.StepTest, ctx gobdd.Context)          {}
func iSetTheIdentityRegisterDocumentAttribute(t gobdd.StepTest, ctx gobdd.Context, attributeType string) {
}
func iRevokeTheIdentityRegisterDocument(t gobdd.StepTest, ctx gobdd.Context) {}
func iGetTheRegisteredDocument(t gobdd.StepTest, ctx gobdd.Context)          {}
func iVerifyTheDocument(t gobdd.StepTest, ctx gobdd.Context)                 {}
func iCreateAnAuthenticationTokenFromTheAgent(t gobdd.StepTest, ctx gobdd.Context, withOrWithoutDelegation string) {
}
func iAddANewOwner(t gobdd.StepTest, ctx gobdd.Context) {}
func iRemoveAOwner(t gobdd.StepTest, ctx gobdd.Context) {}

// Then
func theEntityTypeRegisterDocumentIsCreated(t gobdd.StepTest, ctx gobdd.Context, entityType string) {
}

func theAssociatedEntityTypeIdentityIsReturned(t gobdd.StepTest, ctx gobdd.Context, entityType string) {
}

func theEntityTypeOwnsTheDocument(t gobdd.StepTest, ctx gobdd.Context, entityType string) {}

func theUserDocumentIsCreatedAndRegistered(t gobdd.StepTest, ctx gobdd.Context) {
	user := ctxRegisteredUser.GetRegisteredIdentity(t, ctx)

	doc, err := advancedapi.GetRegisterDocument(resolver, user.Did())
	assert.NilError(t, err)
	userSeedValue, _ := ctx.GetString(ctxUserSeed)
	userKeyName, _ := ctx.GetString(ctxUserKeyName)
	userIssuerName, _ := ctx.GetString(ctxUserIssuerName)
	assertNewDocAndIdentity(t, ctx, []byte(userSeedValue), userKeyName, userIssuerName, doc, user)
	ctx.Set(ctxRegisteredUserDocument, doc)
}

func theAgentDocumentIsCreatedAndRegistered(t gobdd.StepTest, ctx gobdd.Context) {
	agent := ctxRegisteredAgent.GetRegisteredIdentity(t, ctx)

	doc, err := advancedapi.GetRegisterDocument(resolver, agent.Did())
	assert.NilError(t, err)
	agentSeedValue, _ := ctx.GetString(ctxAgentSeed)
	agentKeyName, _ := ctx.GetString(ctxAgentKeyName)
	agentIssuerName, _ := ctx.GetString(ctxAgentIssuerName)
	assertNewDocAndIdentity(t, ctx, []byte(agentSeedValue), agentKeyName, agentIssuerName, doc, agent)
	ctx.Set(ctxRegisteredAgentDocument, doc)
}

func theTwinDocumentIsCreatedAndRegistered(t gobdd.StepTest, ctx gobdd.Context) {
	twin := ctxRegisteredTwin.GetRegisteredIdentity(t, ctx)

	doc, err := advancedapi.GetRegisterDocument(resolver, twin.Did())
	assert.NilError(t, err)
	twinSeedValue, _ := ctx.GetString(ctxTwinSeed)
	twinKeyName, _ := ctx.GetString(ctxTwinKeyName)
	twinIssuerName, _ := ctx.GetString(ctxTwinIssuerName)
	assertNewDocAndIdentity(t, ctx, []byte(twinSeedValue), twinKeyName, twinIssuerName, doc, twin)
	ctx.Set(ctxRegisteredTwinDocument, doc)
}

func theUserAndAgentDocumentsAreRegisteredWithAuthenticationDelegation(t gobdd.StepTest, ctx gobdd.Context) {
	userDoc := ctxRegisteredUserDocument.GetRegisteredDocument(t, ctx)
	agentDoc := ctxRegisteredAgentDocument.GetRegisteredDocument(t, ctx)

	assert.Assert(t, len(userDoc.DelegateAuthentication) == 1)
	assert.Assert(t, userDoc.DelegateAuthentication[0].Revoked == false)

	agent := ctxRegisteredAgent.GetRegisteredIdentity(t, ctx)

	expectedController := fmt.Sprintf("%s%s", agent.Did(), identity.MakeName(identity.Agent))
	assert.Assert(t, userDoc.DelegateAuthentication[0].Controller == expectedController)

	// TODO: this could be a separate step/assertion
	// NOTE: because this is auth delegation, the issuer is agent, subject is user
	isAllowedFor, err := register.IsAllowFor(resolver, agent.Issuer(), agentDoc, userDoc, true)
	assert.NilError(t, err)
	assert.Assert(t, isAllowedFor == true)
}

func theTwinDocumentHasControlDelegationFromTheAgentIdentity(t gobdd.StepTest, ctx gobdd.Context) {
	twin := ctxRegisteredTwin.GetRegisteredIdentity(t, ctx)
	agent := ctxRegisteredAgent.GetRegisteredIdentity(t, ctx)

	// TODO: this could be a separate step/assertion
	twinDoc, err := advancedapi.GetRegisterDocument(resolver, twin.Did())
	assert.NilError(t, err)
	twinSeedValue, _ := ctx.GetString(ctxTwinSeed)
	twinKeyName, _ := ctx.GetString(ctxTwinKeyName)
	expectedTwinIssuerName := "#twin-0"
	assertNewDocAndIdentity(t, ctx, []byte(twinSeedValue), twinKeyName, expectedTwinIssuerName, twinDoc, twin)

	// TODO: this could be a separate step/assertion
	agentDoc, err := advancedapi.GetRegisterDocument(resolver, agent.Did())
	assert.NilError(t, err)
	agentSeedValue, _ := ctx.GetString(ctxAgentSeed)
	agentKeyName, _ := ctx.GetString(ctxAgentKeyName)
	expectedAgentIssuerName := "#agent-0"
	assertNewDocAndIdentity(t, ctx, []byte(agentSeedValue), agentKeyName, expectedAgentIssuerName, agentDoc, agent)

	assert.Assert(t, len(twinDoc.DelegateControl) == 1)
	assert.Assert(t, twinDoc.DelegateControl[0].Revoked == false)

	expectedController := fmt.Sprintf("%s%s", agent.Did(), identity.MakeName(identity.Agent))
	assert.Assert(t, twinDoc.DelegateControl[0].Controller == expectedController)

	// TODO: this could be a separate step/assertion
	// NOTE: because this is control delegation, the issuer is agent, subject is twin
	isAllowedFor, err := register.IsAllowFor(resolver, agent.Issuer(), agentDoc, twinDoc, true)
	assert.NilError(t, err)
	assert.Assert(t, isAllowedFor == true)
}

func theAuthTokenIsValid(t gobdd.StepTest, ctx gobdd.Context) {
	token, _ := ctx.GetString(ctxAuthToken)
	claims, err := register.VerifyAuthentication(resolver, register.JwtToken(token))
	assert.NilError(t, err)
	assert.Assert(t, claims != nil)
}

func theTwinDocumentIsUpdatedWithTheNewOwner(t gobdd.StepTest, ctx gobdd.Context) {

	twin := ctxRegisteredTwin.GetRegisteredIdentity(t, ctx)
	user := ctxRegisteredUser.GetRegisteredIdentity(t, ctx)

	twinDoc, err := advancedapi.GetRegisterDocument(resolver, twin.Did())
	assert.NilError(t, err)

	assert.Assert(t, len(twinDoc.PublicKeys) == 2)

	originalPublicKey := twinDoc.PublicKeyByID("#twin-0")
	assert.Assert(t, originalPublicKey != nil)
	assert.Assert(t, originalPublicKey.Revoked == false)

	newPublicKey := twinDoc.PublicKeyByID("#NewOwner")
	assert.Assert(t, newPublicKey != nil)
	assert.Assert(t, newPublicKey.Revoked == false)
	newOwnerIssuer, _ := register.NewIssuer(twin.Did(), "#NewOwner")

	expectedPublicKey := user.KeyPair().PublicKeyBase58
	assert.Assert(t, newPublicKey.PublicKeyBase58 == expectedPublicKey)

	// TODO: this could be a separate step/assertion
	// NOTE: because this is control delegation, the issuer is twin, subject is twin
	// can the new owner key control the twin, which is in the twinDoc already
	isAllowedFor, err := register.IsAllowFor(resolver, newOwnerIssuer, twinDoc, twinDoc, true)
	assert.NilError(t, err)
	assert.Assert(t, isAllowedFor == true)
}

func theRegisteredIdentityIssuerDidIsEqualToTheDocumentDid(t gobdd.StepTest, ctx gobdd.Context) {
	twin := ctxRegisteredTwin.GetRegisteredIdentity(t, ctx)
	doc := ctxRetrievedDoc.GetRegisteredDocument(t, ctx)
	assert.Assert(t, twin.Did() == doc.ID)
}

func theRegisterDocumentHasTheRegisteredIdentityPublicKey(t gobdd.StepTest, ctx gobdd.Context) {
	twin := ctxRegisteredTwin.GetRegisteredIdentity(t, ctx)
	doc := ctxRetrievedDoc.GetRegisteredDocument(t, ctx)
	assertDocContainsPubKey(t, doc, twin.KeyPair().PublicKeyBase58)
}

func assertDocContainsPubKey(t gobdd.StepTest, doc *register.RegisterDocument, expectedPublicKey string) {
	assert.Assert(t, expectedPublicKey != "")
	found := false
	for _, docKey := range doc.PublicKeys {
		if docKey.PublicKeyBase58 == expectedPublicKey {
			found = true
			break
		}
	}
	assert.Assert(t, found, "Public key not found in the document.")
}

func docKeysContain(t gobdd.StepTest, docKeys []register.RegisterPublicKey, publicKeyName string, revoked bool) bool {
	if publicKeyName == "" {
		t.Errorf("Given public key name is empty.", publicKeyName)
		return false
	}
	for _, docKey := range docKeys {
		if docKey.ID == publicKeyName {
			return docKey.Revoked == revoked
		}
	}
	t.Errorf("Public key \"%s\" not found in the document given keys.", publicKeyName)
	return false
}

func docKeysDoNotContain(t gobdd.StepTest, docKeys []register.RegisterPublicKey, publicKeyName string) bool {
	if publicKeyName == "" {
		t.Errorf("Given public key name is empty.")
		return false
	}
	for _, docKey := range docKeys {
		if docKey.ID == publicKeyName {
			t.Errorf("Public key \"%s\" found in the document given keys.", publicKeyName)
			return false
		}
	}
	return true
}

func docDelegationProofsContain(t gobdd.StepTest, docDelegationProofs []register.RegisterDelegationProof, delegationName string, revoked bool) bool {
	if delegationName == "" {
		t.Errorf("Given delegation name is empty.")
		return false
	}
	for _, pr := range docDelegationProofs {
		if pr.ID == delegationName {
			return pr.Revoked == revoked
		}
	}
	t.Errorf("Delegation name \"%s\" not found in the document given proofs.", delegationName)
	return false
}

func theRegisteredIdentityIsAllowed(t gobdd.StepTest, ctx gobdd.Context) {
	allowedForAuth, err := ctx.GetBool(ctxAllowedForAuth)
	assert.NilError(t, err)
	assert.Assert(t, allowedForAuth == true)
	allowedForControl, err := ctx.GetBool(ctxAllowedForControl)
	assert.NilError(t, err)
	assert.Assert(t, allowedForControl)
}

func theRegisterDocumentHasSeveralPublicKeys(t gobdd.StepTest, ctx gobdd.Context) {
	doc := ctxRetrievedDoc.GetRegisteredDocument(t, ctx)
	allOwnersPubKeys, _ := ctx.Get(ctxAllOwnersPubKeys)

	assert.Equal(t, len(doc.PublicKeys), 3)
	for _, pubKey := range allOwnersPubKeys.([]string) {
		assertDocContainsPubKey(t, doc, pubKey)
	}
}

func theNewOwnerIsAllowedForAuthenticationAndControlOnTheDocument(t gobdd.StepTest, ctx gobdd.Context) {
	newTwinName, _ := ctx.GetString(ctxOtherTwinIdentityName)
	newTwinPublicKeyBase58, _ := ctx.GetString(ctxOtherTwinIdentityPubKey)
	assert.Assert(t, newTwinName != "")
	assert.Assert(t, newTwinPublicKeyBase58 != "")

	initialOwner := ctxRegisteredTwin.GetRegisteredIdentity(t, ctx)
	doc, err := advancedapi.GetRegisterDocument(resolver, initialOwner.Did())
	assert.NilError(t, err)
	newIssuer, err := advancedapi.GetIssuerByPublicKey(doc, newTwinPublicKeyBase58)
	assert.NilError(t, err)
	assert.Assert(t, initialOwner.Name() != newIssuer.Name)
	assert.Assert(t, initialOwner.Did() == newIssuer.Did)

	assert.Assert(t, len(doc.PublicKeys) == 2)
	assert.Assert(t, docKeysContain(t, doc.PublicKeys, initialOwner.Name(), false))
	assert.Assert(t, docKeysContain(t, doc.PublicKeys, newTwinName, false))
	assert.NilError(t, register.ValidateAllowedForAuth(resolver, initialOwner.Issuer(), doc.ID))
	assert.NilError(t, register.ValidateAllowedForControl(resolver, initialOwner.Issuer(), doc.ID))
	assert.NilError(t, register.ValidateAllowedForAuth(resolver, newIssuer, doc.ID))
	assert.NilError(t, register.ValidateAllowedForControl(resolver, newIssuer, doc.ID))
}

func theRemovedOwnerIsNotAllowedForAuthenticationOrControlOnTheDocument(t gobdd.StepTest, ctx gobdd.Context) {
	removedTwinOwnerName, _ := ctx.GetString(ctxOtherTwinIdentityName)
	assert.Assert(t, removedTwinOwnerName != "")
	initialOwner := ctxRegisteredTwin.GetRegisteredIdentity(t, ctx)
	otherIssuer, _ := ctx.Get(ctxOtherTwinIdentityIssuer)
	removedIssuer := otherIssuer.(*register.Issuer)
	assert.Assert(t, removedIssuer.Did == initialOwner.Did())
	doc, err := advancedapi.GetRegisterDocument(resolver, initialOwner.Did())
	assert.NilError(t, err)

	assert.Assert(t, len(doc.PublicKeys) == 1)
	assert.Assert(t, docKeysContain(t, doc.PublicKeys, initialOwner.Name(), false))
	assert.Assert(t, docKeysDoNotContain(t, doc.PublicKeys, removedTwinOwnerName))
	assert.NilError(t, register.ValidateAllowedForAuth(resolver, initialOwner.Issuer(), doc.ID))
	assert.NilError(t, register.ValidateAllowedForControl(resolver, initialOwner.Issuer(), doc.ID))
	assert.Assert(t, register.ValidateAllowedForAuth(resolver, removedIssuer, doc.ID) != nil)
	assert.Assert(t, register.ValidateAllowedForControl(resolver, removedIssuer, doc.ID) != nil)
}

func theRevokedOwnerIsNotAllowedForAuthenticationOrControlOnTheDocument(t gobdd.StepTest, ctx gobdd.Context) {
	revokedTwinOwnerName, _ := ctx.GetString(ctxOtherTwinIdentityName)
	assert.Assert(t, revokedTwinOwnerName != "")
	revokedTwinPublicKeyBase58, _ := ctx.GetString(ctxOtherTwinIdentityPubKey)
	assert.Assert(t, revokedTwinPublicKeyBase58 != "")
	initialOwner := ctxRegisteredTwin.GetRegisteredIdentity(t, ctx)
	doc, err := advancedapi.GetRegisterDocument(resolver, initialOwner.Did())
	assert.NilError(t, err)
	revokedIssuer, err := advancedapi.GetIssuerByPublicKey(doc, revokedTwinPublicKeyBase58)
	otherIssuer, _ := ctx.Get(ctxOtherTwinIdentityIssuer)
	assert.DeepEqual(t, revokedIssuer, otherIssuer)
	assert.Assert(t, revokedIssuer.Did == initialOwner.Did())

	assert.Assert(t, len(doc.PublicKeys) == 2)
	assert.Assert(t, docKeysContain(t, doc.PublicKeys, initialOwner.Name(), false))
	assert.Assert(t, docKeysContain(t, doc.PublicKeys, revokedTwinOwnerName, true))
	assert.NilError(t, register.ValidateAllowedForAuth(resolver, initialOwner.Issuer(), doc.ID))
	assert.NilError(t, register.ValidateAllowedForControl(resolver, initialOwner.Issuer(), doc.ID))
	assert.Assert(t, register.ValidateAllowedForAuth(resolver, revokedIssuer, doc.ID) != nil)
	assert.Assert(t, register.ValidateAllowedForControl(resolver, revokedIssuer, doc.ID) != nil)
}

func theAuthenticationKeyOwnerIsAllowedForAuthenticationOnTheDocument(t gobdd.StepTest, ctx gobdd.Context) {
	initialOwner := ctxRegisteredTwin.GetRegisteredIdentity(t, ctx)
	doc, err := advancedapi.GetRegisterDocument(resolver, initialOwner.Did())
	assert.NilError(t, err)
	newAuthKeyTwinName, _ := ctx.GetString(ctxOtherTwinIdentityName)
	newAuthKeyTwinIssuer, err := register.NewIssuer(doc.ID, newAuthKeyTwinName)
	assert.NilError(t, err)

	assert.Assert(t, len(doc.AuthenticationKeys) == 1)
	assert.Assert(t, docKeysContain(t, doc.AuthenticationKeys, newAuthKeyTwinName, false))
	assert.NilError(t, register.ValidateAllowedForAuth(resolver, initialOwner.Issuer(), doc.ID))
	assert.NilError(t, register.ValidateAllowedForAuth(resolver, newAuthKeyTwinIssuer, doc.ID))
	assert.Assert(t, register.ValidateAllowedForControl(resolver, newAuthKeyTwinIssuer, doc.ID) != nil)
}

func theRemovedAuthenticationKeyOwnerIsNotAllowedForAuthenticationOnTheDocument(t gobdd.StepTest, ctx gobdd.Context) {
	initialOwner := ctxRegisteredTwin.GetRegisteredIdentity(t, ctx)
	doc, err := advancedapi.GetRegisterDocument(resolver, initialOwner.Did())
	assert.NilError(t, err)
	removedTwinName, _ := ctx.GetString(ctxOtherTwinIdentityName)
	removedTwinIssuer, err := register.NewIssuer(doc.ID, removedTwinName)
	assert.NilError(t, err)

	assert.Assert(t, len(doc.AuthenticationKeys) == 0)
	assert.Assert(t, docKeysDoNotContain(t, doc.AuthenticationKeys, removedTwinName))
	assert.Assert(t, register.ValidateAllowedForAuth(resolver, removedTwinIssuer, doc.ID) != nil)
	assert.Assert(t, register.ValidateAllowedForControl(resolver, removedTwinIssuer, doc.ID) != nil)
}

func theRevokedAuthenticationKeyOwnerIsNotAllowedForAuthenticationOnTheDocument(t gobdd.StepTest, ctx gobdd.Context) {
	initialOwner := ctxRegisteredTwin.GetRegisteredIdentity(t, ctx)
	doc, err := advancedapi.GetRegisterDocument(resolver, initialOwner.Did())
	assert.NilError(t, err)
	revokedTwinName, _ := ctx.GetString(ctxOtherTwinIdentityName)
	revokedTwinIssuer, err := register.NewIssuer(doc.ID, revokedTwinName)
	assert.NilError(t, err)

	assert.Assert(t, len(doc.AuthenticationKeys) == 1)
	assert.Assert(t, docKeysContain(t, doc.AuthenticationKeys, revokedTwinName, true))
	assert.Assert(t, register.ValidateAllowedForAuth(resolver, revokedTwinIssuer, doc.ID) != nil)
	assert.Assert(t, register.ValidateAllowedForControl(resolver, revokedTwinIssuer, doc.ID) != nil)
}

func theOtherIdentityIsAllowedForControlOnTheInitialIdentityDocument(t gobdd.StepTest, ctx gobdd.Context) {
	initialIdentity := ctxRegisteredTwin.GetRegisteredIdentity(t, ctx)
	doc, err := advancedapi.GetRegisterDocument(resolver, initialIdentity.Did())
	assert.NilError(t, err)
	delegationName, _ := ctx.GetString(ctxDelegationName)
	newTwinIdentity := ctxOtherRegisteredTwin.GetRegisteredIdentity(t, ctx)

	assert.Assert(t, len(doc.DelegateControl) == 1)
	assert.Assert(t, docDelegationProofsContain(t, doc.DelegateControl, delegationName, false))
	assert.NilError(t, register.ValidateAllowedForControl(resolver, newTwinIdentity.Issuer(), doc.ID))
}

func theDelegatedRegisteredIdentityIsAllowedForControlOnTheDocument(t gobdd.StepTest, ctx gobdd.Context) {
	initialIdentity := ctxRegisteredTwin.GetRegisteredIdentity(t, ctx)
	doc, err := advancedapi.GetRegisterDocument(resolver, initialIdentity.Did())
	assert.NilError(t, err)
	delegationName, _ := ctx.GetString(ctxDelegationName)
	otherIdentity := ctxOtherRegisteredTwin.GetRegisteredIdentity(t, ctx)

	assert.Assert(t, len(doc.DelegateControl) == 1)
	assert.Assert(t, docDelegationProofsContain(t, doc.DelegateControl, delegationName, false))
	assert.NilError(t, register.ValidateAllowedForControl(resolver, otherIdentity.Issuer(), initialIdentity.Did()))
}

func theDelegatedRegisteredIdentityIsNotAllowedForControlOnTheDocumentAfterDelegationRemove(t gobdd.StepTest, ctx gobdd.Context) {
	initialIdentity := ctxRegisteredTwin.GetRegisteredIdentity(t, ctx)
	doc, err := advancedapi.GetRegisterDocument(resolver, initialIdentity.Did())
	assert.NilError(t, err)
	otherIdentity := ctxOtherRegisteredTwin.GetRegisteredIdentity(t, ctx)

	assert.Assert(t, len(doc.DelegateControl) == 0)
	assert.Assert(t, register.ValidateAllowedForControl(resolver, otherIdentity.Issuer(), initialIdentity.Did()) != nil)
}

func theDelegatedRegisteredIdentityIsNotAllowedForControlOnTheDocumentAfterDelegationRevoke(t gobdd.StepTest, ctx gobdd.Context) {
	initialIdentity := ctxRegisteredTwin.GetRegisteredIdentity(t, ctx)
	doc, err := advancedapi.GetRegisterDocument(resolver, initialIdentity.Did())
	assert.NilError(t, err)
	delegationName, _ := ctx.GetString(ctxDelegationName)
	otherIdentity := ctxOtherRegisteredTwin.GetRegisteredIdentity(t, ctx)

	assert.Assert(t, len(doc.DelegateControl) == 1)
	assert.Assert(t, docDelegationProofsContain(t, doc.DelegateControl, delegationName, true))
	assert.Assert(t, register.ValidateAllowedForControl(resolver, otherIdentity.Issuer(), initialIdentity.Did()) != nil)
}

func iDBIsAllowedForAuthenticationOnTheDocumentDocA(t gobdd.StepTest, ctx gobdd.Context) {
	initialIdentity := ctxRegisteredTwin.GetRegisteredIdentity(t, ctx)
	doc, err := advancedapi.GetRegisterDocument(resolver, initialIdentity.Did())
	assert.NilError(t, err)
	delegationName, _ := ctx.GetString(ctxDelegationName)
	newTwinIdentity := ctxOtherRegisteredTwin.GetRegisteredIdentity(t, ctx)

	assert.Assert(t, len(doc.DelegateAuthentication) == 1)
	assert.Assert(t, docDelegationProofsContain(t, doc.DelegateAuthentication, delegationName, false))
	assert.NilError(t, register.ValidateAllowedForAuth(resolver, newTwinIdentity.Issuer(), doc.ID))
}

func theDelegatedRegisteredIdentityIsStillAllowedForAuthenticationOnTheDocument(t gobdd.StepTest, ctx gobdd.Context) {
	initialIdentity := ctxRegisteredTwin.GetRegisteredIdentity(t, ctx)
	initialTwinDoc, err := advancedapi.GetRegisterDocument(resolver, initialIdentity.Did())
	assert.NilError(t, err)
	otherIdentity := ctxOtherRegisteredTwin.GetRegisteredIdentity(t, ctx)
	otherTwinDoc, err := advancedapi.GetRegisterDocument(resolver, otherIdentity.Did())
	assert.NilError(t, err)
	extraOwnerName, _ := ctx.GetString(ctxOtherTwinIdentityExtraOwnerName)
	assert.Assert(t, extraOwnerName != "")
	extraOwnerIssuer, err := register.NewIssuer(otherTwinDoc.ID, extraOwnerName)
	assert.NilError(t, err)

	assert.Assert(t, len(otherTwinDoc.PublicKeys) == 2)
	assert.Assert(t, docKeysContain(t, otherTwinDoc.PublicKeys, otherIdentity.Name(), false))
	assert.Assert(t, docKeysContain(t, otherTwinDoc.PublicKeys, extraOwnerName, true))
	assert.NilError(t, register.ValidateAllowedForAuth(resolver, extraOwnerIssuer, initialTwinDoc.ID))
}

func theDelegatedRegisteredIdentityIsStillAllowedForControlOnTheDocument(t gobdd.StepTest, ctx gobdd.Context) {
	initialIdentity := ctxRegisteredTwin.GetRegisteredIdentity(t, ctx)
	initialTwinDoc, err := advancedapi.GetRegisterDocument(resolver, initialIdentity.Did())
	assert.NilError(t, err)
	otherIdentity := ctxOtherRegisteredTwin.GetRegisteredIdentity(t, ctx)
	otherTwinDoc, err := advancedapi.GetRegisterDocument(resolver, otherIdentity.Did())
	assert.NilError(t, err)
	extraOwnerName, _ := ctx.GetString(ctxOtherTwinIdentityExtraOwnerName)
	assert.Assert(t, extraOwnerName != "")
	extraOwnerIssuer, err := register.NewIssuer(otherTwinDoc.ID, extraOwnerName)
	assert.NilError(t, err)

	assert.Assert(t, len(otherTwinDoc.PublicKeys) == 2)
	assert.Assert(t, docKeysContain(t, otherTwinDoc.PublicKeys, otherIdentity.Name(), false))
	assert.Assert(t, docKeysContain(t, otherTwinDoc.PublicKeys, extraOwnerName, true))
	assert.NilError(t, register.ValidateAllowedForControl(resolver, extraOwnerIssuer, initialTwinDoc.ID))
}

func theDelegatedRegisteredIdentityIsNotAllowedForAuthenticationOnTheDocumentAnymore(t gobdd.StepTest, ctx gobdd.Context) {
	initialIdentity := ctxRegisteredTwin.GetRegisteredIdentity(t, ctx)
	initialTwinDoc, err := advancedapi.GetRegisterDocument(resolver, initialIdentity.Did())
	assert.NilError(t, err)
	otherIdentity := ctxOtherRegisteredTwin.GetRegisteredIdentity(t, ctx)
	otherTwinDoc, err := advancedapi.GetRegisterDocument(resolver, otherIdentity.Did())
	assert.NilError(t, err)
	extraOwnerName, _ := ctx.GetString(ctxOtherTwinIdentityExtraOwnerName)
	assert.Assert(t, extraOwnerName != "")
	extraOwnerIssuer, err := register.NewIssuer(otherTwinDoc.ID, extraOwnerName)
	assert.NilError(t, err)

	assert.Assert(t, len(otherTwinDoc.PublicKeys) == 1)
	assert.Assert(t, docKeysContain(t, otherTwinDoc.PublicKeys, otherIdentity.Name(), false))
	assert.Assert(t, register.ValidateAllowedForAuth(resolver, extraOwnerIssuer, initialTwinDoc.ID) != nil)
}

func theDelegatedRegisteredIdentityIsNotAllowedForControlOnTheDocumentAnymore(t gobdd.StepTest, ctx gobdd.Context) {
	initialIdentity := ctxRegisteredTwin.GetRegisteredIdentity(t, ctx)
	initialTwinDoc, err := advancedapi.GetRegisterDocument(resolver, initialIdentity.Did())
	assert.NilError(t, err)
	otherIdentity := ctxOtherRegisteredTwin.GetRegisteredIdentity(t, ctx)
	otherTwinDoc, err := advancedapi.GetRegisterDocument(resolver, otherIdentity.Did())
	assert.NilError(t, err)
	extraOwnerName, _ := ctx.GetString(ctxOtherTwinIdentityExtraOwnerName)
	assert.Assert(t, extraOwnerName != "")
	extraOwnerIssuer, err := register.NewIssuer(otherTwinDoc.ID, extraOwnerName)
	assert.NilError(t, err)

	assert.Assert(t, len(otherTwinDoc.PublicKeys) == 1)
	assert.Assert(t, docKeysContain(t, otherTwinDoc.PublicKeys, otherIdentity.Name(), false))
	assert.Assert(t, register.ValidateAllowedForControl(resolver, extraOwnerIssuer, initialTwinDoc.ID) != nil)
}

func theDelegatedRegisteredIdentityIsNotAllowedForAuthenticationOnTheDocumentAfterDelegationRemove(t gobdd.StepTest, ctx gobdd.Context) {
	initialIdentity := ctxRegisteredTwin.GetRegisteredIdentity(t, ctx)
	doc, err := advancedapi.GetRegisterDocument(resolver, initialIdentity.Did())
	assert.NilError(t, err)
	otherIdentity := ctxOtherRegisteredTwin.GetRegisteredIdentity(t, ctx)

	assert.Assert(t, len(doc.DelegateAuthentication) == 0)
	assert.Assert(t, register.ValidateAllowedForAuth(resolver, otherIdentity.Issuer(), initialIdentity.Did()) != nil)
}

func theDelegatedRegisteredIdentityIsNotAllowedForAuthenticationOnTheDocumentAfterDelegationRevoke(t gobdd.StepTest, ctx gobdd.Context) {
	initialIdentity := ctxRegisteredTwin.GetRegisteredIdentity(t, ctx)
	doc, err := advancedapi.GetRegisterDocument(resolver, initialIdentity.Did())
	assert.NilError(t, err)
	delegationName, _ := ctx.GetString(ctxDelegationName)
	otherIdentity := ctxOtherRegisteredTwin.GetRegisteredIdentity(t, ctx)

	assert.Assert(t, len(doc.DelegateAuthentication) == 1)
	assert.Assert(t, docDelegationProofsContain(t, doc.DelegateAuthentication, delegationName, true))
	assert.Assert(t, register.ValidateAllowedForAuth(resolver, otherIdentity.Issuer(), initialIdentity.Did()) != nil)
}

func theControllerIsAllowedForControlAndAuthentication(t gobdd.StepTest, ctx gobdd.Context) {
	initialIdentity := ctxRegisteredTwin.GetRegisteredIdentity(t, ctx)
	doc, err := advancedapi.GetRegisterDocument(resolver, initialIdentity.Did())
	assert.NilError(t, err)
	otherIdentity := ctxOtherRegisteredTwin.GetRegisteredIdentity(t, ctx)

	assert.NilError(t, register.ValidateAllowedForAuth(resolver, otherIdentity.Issuer(), doc.ID))
	assert.NilError(t, register.ValidateAllowedForControl(resolver, otherIdentity.Issuer(), doc.ID))
}

func theIdentityTypeDocumentIsUpdatedWithTheNewName(t gobdd.StepTest, ctx gobdd.Context, identityType string) {
}
func theIdentityIsValid(t gobdd.StepTest, ctx gobdd.Context) {}
func theDocumentIsUpdatedWithTheAgentAuthenticationDelegation(t gobdd.StepTest, ctx gobdd.Context, identityType string) {
}
func theDocumentIsUpdatedWithTheNewAttribute(t gobdd.StepTest, ctx gobdd.Context, attributeType string) {
}
func theDocumentIsRevoked(t gobdd.StepTest, ctx gobdd.Context)               {}
func theCorrespondingDocumentIsReturned(t gobdd.StepTest, ctx gobdd.Context) {}
func theDocumentIsValid(t gobdd.StepTest, ctx gobdd.Context)                 {}
func aValidationErrorIsRaised(t gobdd.StepTest, ctx gobdd.Context)           {}
func theTokenIsOrIsNotAuthorizedForAuthentication(t gobdd.StepTest, ctx gobdd.Context, isOrIsNot string) {
}
func theNewOwnerKeyHasBeenAddedToTheDocument(t gobdd.StepTest, ctx gobdd.Context) {}
func theKeyHasBeenRemovedFromTheDocument(t gobdd.StepTest, ctx gobdd.Context)     {}

// Features
func TestScenarios(t *testing.T) {
	suite := gobdd.NewSuite(t) //gobdd.WithTags([]string{"@wip"}),
	//gobdd.WithIgnoredTags([]string{"@broken"}),

	// Given
	suite.AddStep(`^a resolver exists$`, aResolverExists)
	suite.AddStep(`^a user seed "([^"]+)"$`, userSeed)
	suite.AddStep(`^a user key name "([^"]+)"$`, userKeyName)
	suite.AddStep(`^a user issuer name "([^"]+)"$`, userIssuerName)
	suite.AddStep(`^an agent seed "([^"]+)"$`, agentSeed)
	suite.AddStep(`^an agent key name "([^"]+)"$`, agentKeyName)
	suite.AddStep(`^a agent issuer name "([^"]+)"$`, agentIssuerName)
	suite.AddStep(`^a twin seed "([^"]+)"$`, twinSeed)
	suite.AddStep(`^a twin key name "([^"]+)"$`, twinKeyName)
	suite.AddStep(`^a twin issuer name "([^"]+)"$`, twinIssuerName)
	suite.AddStep(`^a delegation name "([^"]+)"$`, aDelegationName)
	suite.AddStep(`^a new owner key name is "([^"]+)"$`, aNewOwnerKeyNameIs)

	suite.AddStep(`^the legacy seed method$`, theLegacySeedMethod)
	suite.AddStep(`^an existing registered "(agent|twin|user)" identity$`, anExistingRegisteredEntityType)

	suite.AddStep(`^a registered user$`, aRegisteredUser)
	suite.AddStep(`^a registered twin$`, aRegisteredTwin)
	suite.AddStep(`^a registered agent$`, aRegisteredAgent)
	suite.AddStep(`^a registered identity with name "([^"]+)"$`, aRegisteredIdentityWithName)
	suite.AddStep(`^a another registered identity with name "([^"]+)"$`, aAnotherRegisteredIdentityWithName)
	suite.AddStep(`^a registered identity owning the document$`, aRegisteredIdentityOwningTheDocument)
	suite.AddStep(`^a register document with several owners$`, aRegisterDocumentWithSeveralOwners)
	suite.AddStep(`^a new twin "([^"]+)" public key$`, aNewTwinNameAndPublicKey)
	suite.AddStep(`^a another twin "([^"]+)" owner$`, aAnotherTwinOwner)
	suite.AddStep(`^a another twin "([^"]+)" authentication public key$`, aAnotherTwinAuthenticationPublicKey)
	suite.AddStep(`^a delegation proof for document of "([^"]+)" created by "([^"]+)"$`, aDelegationProofCreatedForBy)
	suite.AddStep(`^a register identity IDA owning the document DocA with an auth delegation proof created by a delegated registered identity$`,
		aRegisterIdentityIDAOwningTheDocumentDocAWithAnAuthDelegationProofCreatedByADelegatedRegisteredIdentity)
	suite.AddStep(`^a register identity IDA owning the document DocA and a controller \(registered identity\)$`,
		aRegisterIdentityIDAOwningTheDocumentDocAAndAControllerRegisteredIdentity)
	suite.AddStep(`^a another registered identity with name "([^"]+)" and an extra owner "([^"]+)"$`, aAnotherRegisteredIdentityWithNameAndAnExtraOwner)
	suite.AddStep(`^a register identity IDA owning the document DocA with a control delegation proof created by a delegated registered identity with several owner$`,
		aRegisterIdentityIDAOwningTheDocumentDocAWithAControlDelegationProofCreatedByADelegatedRegisteredIdentityWithSeveralOwner)
	suite.AddStep(`^an? (agent|twin|user) key name "([^"]+)" from a registered identity$`, aIdentityTypeSeedAndAIdentityTypeKeyNameFromARegisteredIdentity)
	suite.AddStep(`^a controller issuer$`, aControllerIssuer)
	suite.AddStep(`^a creator$`, aCreator)
	suite.AddStep(`^a not revoked registered identity$`, aNotRevokedRegisteredIdentity)
	suite.AddStep(`^an existing registered identity$`, anExistingRegisteredIdentity)
	suite.AddStep(`^an existing registered document$`, anExistingRegisteredDocument)
	suite.AddStep(`^a corrupted registered document$`, aCorruptedRegisteredDocument)
	suite.AddStep(`^a register user document$`, aRegisterUserDocument)
	suite.AddStep(`^a register agent document "with(out)?" authentication delegation$`, aRegisterAgentDocument)
	suite.AddStep(`^a new owner key name an registered identity register$`, aNewOwnerKeyNameAnRegisteredIdentityRegister)
	suite.AddStep(`^an owner key name an registered identity register$`, aOwnerKeyNameAnRegisteredIdentityRegister)

	suite.AddStep(`^the auth token duration is "([^"]+)"$`, theAuthTokenDurationIs)
	suite.AddStep(`^the target audience is "([^"]+)"$`, theTargetAudienceIs)

	// When
	suite.AddStep(`^I create user and agent with authentication delegation$`, iCreateUserAndAgentWithAuthenticationDelegation)
	suite.AddStep(`^I create a user$`, iCreateAUser)
	suite.AddStep(`^I create an agent$`, iCreateAnAgent)
	suite.AddStep(`^I create a twin$`, iCreateATwin)
	suite.AddStep(`^I delegate control$`, iDelegateControl)
	suite.AddStep(`^I create an agent auth token$`, iCreateAnAgentAuthToken)
	suite.AddStep(`^the user takes ownership of the registered twin$`, theUserTakesOwnershipOfTheRegisteredTwin)
	suite.AddStep(`^I get the associated document$`, iGetTheAssociatedDocument)
	suite.AddStep(`^I check if the registered identity is allowed for control and authentication on the associated document$`,
		iCheckIfTheRegisteredIdentityIsAllowedForControlAndAuthenticationOnTheAssociatedDocument)
	suite.AddStep(`^I add the new owner to the document$`, iAddTheNewOwnerToTheDocument)
	suite.AddStep(`^I remove the other owner from the document$`, iRemoveTheOtherOwnerFromTheDocument)
	suite.AddStep(`^I revoke the other owner key$`, iRevokeTheOtherOwnerKey)
	suite.AddStep(`^I add the new authentication key to the document$`, iAddTheNewAuthenticationKeyToTheDocument)
	suite.AddStep(`^I remove the authentication key from the document$`, iRemoveTheAuthenticationKeyFromTheDocument)
	suite.AddStep(`^I revoke the authentication key from the document$`, iRevokeTheAuthenticationKeyFromTheDocument)
	suite.AddStep(`^one identity delegates control to another with delegation name "([^"]+)"$`, iDADelegatesControlToIDB)
	suite.AddStep(`^one identity delegates control to another with extra owner with delegation name "([^"]+)"$`, iDADelegatesControlToIDBWithExtraOwner)
	suite.AddStep(`^I add the control delegation proof "([^"]+)" to the document$`, iAddTheControlDelegationProofToTheDocument)
	suite.AddStep(`^I remove the control delegation proof from the document$`, iRemoveTheControlDelegationProofFromTheDocument)
	suite.AddStep(`^I revoke the control delegation proof$`, iRevokeTheControlDelegationProof)
	suite.AddStep(`^one identity delegates authentication to another with delegation name "([^"]+)"$`, iDADelegatesAuthenticationToIDB)
	suite.AddStep(`^one identity delegates authentication to another with extra owner with delegation name "([^"]+)"$`, iDADelegatesAuthenticationToIDBWithExtraOwner)
	suite.AddStep(`^I add the authentication delegation proof "([^"]+)" to the document$`, iAddTheAuthenticationDelegationProofToTheDocument)
	suite.AddStep(`^I remove the authentication delegation proof from the document$`, iRemoveTheAuthenticationDelegationProofFromTheDocument)
	suite.AddStep(`^I revoke the authentication delegation proof$`, iRevokeTheAuthenticationDelegationProof)
	suite.AddStep(`^I set the controller on my document$`, iSetTheControllerOnMyDocument)
	suite.AddStep(`^the delegated identity owner used for the proof is revoked$`, theDelegatedIdentityOwnerUsedForTheProofIsRevoked)
	suite.AddStep(`^the delegated identity owner used for the proof is removed$`, theDelegatedIdentityOwnerUsedForTheProofIsRemoved)
	suite.AddStep(`^I create the "(agent|twin|user)" overriding the document with a new name$`, iCreateTheIdentityOverridingTheDocumentWithANewName)
	suite.AddStep(`^I get the "(agent|twin|user)" identity$`, iGetTheIdentity)
	suite.AddStep(`^User delegates authentication to agent$`, userDelegatesAuthenticationToAgent)
	suite.AddStep(`^Twin delegates control to agent$`, twinDelegatesControlToAgent)
	suite.AddStep(`^I set the identity register document "(controller|creator)"$`, iSetTheIdentityRegisterDocumentAttribute)
	suite.AddStep(`^I revoke the identity register document$`, iRevokeTheIdentityRegisterDocument)
	suite.AddStep(`^I get the registered document$`, iGetTheRegisteredDocument)
	suite.AddStep(`^I verify the document$`, iVerifyTheDocument)
	suite.AddStep(`^I create an authentication token from the agent "with(out)?" delegation$`, iCreateAnAuthenticationTokenFromTheAgent)
	suite.AddStep(`^I add a new owner$`, iAddANewOwner)
	suite.AddStep(`^I remove a owner$`, iRemoveAOwner)

	// Then
	suite.AddStep(`^the "(agent|twin|user)" register document is created$`, theEntityTypeRegisterDocumentIsCreated)
	suite.AddStep(`^the associated "(agent|twin|user)" identity is returned$`, theAssociatedEntityTypeIdentityIsReturned)
	suite.AddStep(`^the "(agent|twin|user)" owns the document$`, theEntityTypeOwnsTheDocument)
	suite.AddStep(`^the twin document is created and registered$`, theTwinDocumentIsCreatedAndRegistered)
	suite.AddStep(`^the user document is created and registered$`, theUserDocumentIsCreatedAndRegistered)
	suite.AddStep(`^the agent document is created and registered$`, theAgentDocumentIsCreatedAndRegistered)

	suite.AddStep(`^the user and agent documents are registered with authentication delegation$`,
		theUserAndAgentDocumentsAreRegisteredWithAuthenticationDelegation)
	suite.AddStep(`^the twin document has control delegation from the agent identity$`, theTwinDocumentHasControlDelegationFromTheAgentIdentity)
	suite.AddStep(`^the auth token is valid$`, theAuthTokenIsValid)
	suite.AddStep(`^the twin document is updated with the new owner$`, theTwinDocumentIsUpdatedWithTheNewOwner)
	suite.AddStep(`^The registered identity issuer did is equal to the document did$`, theRegisteredIdentityIssuerDidIsEqualToTheDocumentDid)
	suite.AddStep(`^The register document has the registered identity public key$`, theRegisterDocumentHasTheRegisteredIdentityPublicKey)
	suite.AddStep(`^the registered identity is allowed$`, theRegisteredIdentityIsAllowed)
	suite.AddStep(`^The register document has several public keys$`, theRegisterDocumentHasSeveralPublicKeys)
	suite.AddStep(`^the new owner is allowed for authentication and control on the document$`,
		theNewOwnerIsAllowedForAuthenticationAndControlOnTheDocument)
	suite.AddStep(`^the removed owner is not allowed for authentication or control on the document$`,
		theRemovedOwnerIsNotAllowedForAuthenticationOrControlOnTheDocument)
	suite.AddStep(`^the revoked owner is not allowed for authentication or control on the document$`,
		theRevokedOwnerIsNotAllowedForAuthenticationOrControlOnTheDocument)
	suite.AddStep(`^the authentication key owner is allowed for authentication on the document$`,
		theAuthenticationKeyOwnerIsAllowedForAuthenticationOnTheDocument)
	suite.AddStep(`^the removed authentication key owner is not allowed for authentication on the document$`,
		theRemovedAuthenticationKeyOwnerIsNotAllowedForAuthenticationOnTheDocument)
	suite.AddStep(`^the revoked authentication key owner is not allowed for authentication on the document$`,
		theRevokedAuthenticationKeyOwnerIsNotAllowedForAuthenticationOnTheDocument)
	suite.AddStep(`^the other identity is allowed for control on the initial identity document$`,
		theOtherIdentityIsAllowedForControlOnTheInitialIdentityDocument)
	suite.AddStep(`^the delegated registered identity is allowed for control on the document$`,
		theDelegatedRegisteredIdentityIsAllowedForControlOnTheDocument)
	suite.AddStep(`^the delegated registered identity is still allowed for control on the document$`,
		theDelegatedRegisteredIdentityIsStillAllowedForControlOnTheDocument)
	suite.AddStep(`^the delegated registered identity is not allowed for control on the document after delegation remove$`,
		theDelegatedRegisteredIdentityIsNotAllowedForControlOnTheDocumentAfterDelegationRemove)
	suite.AddStep(`^the delegated registered identity is not allowed for control on the document after delegation revoke$`,
		theDelegatedRegisteredIdentityIsNotAllowedForControlOnTheDocumentAfterDelegationRevoke)
	suite.AddStep(`^the other identity is allowed for authentication on the initial identity document$`, iDBIsAllowedForAuthenticationOnTheDocumentDocA)
	suite.AddStep(`^the delegated registered identity is still allowed for authentication on the document$`,
		theDelegatedRegisteredIdentityIsStillAllowedForAuthenticationOnTheDocument)
	suite.AddStep(`^the delegated registered identity is not allowed for authentication on the document anymore$`,
		theDelegatedRegisteredIdentityIsNotAllowedForAuthenticationOnTheDocumentAnymore)
	suite.AddStep(`^the delegated registered identity is not allowed for control on the document anymore$`,
		theDelegatedRegisteredIdentityIsNotAllowedForControlOnTheDocumentAnymore)
	suite.AddStep(`^the delegated registered identity is not allowed for authentication on the document after delegation remove$`,
		theDelegatedRegisteredIdentityIsNotAllowedForAuthenticationOnTheDocumentAfterDelegationRemove)
	suite.AddStep(`^the delegated registered identity is not allowed for authentication on the document after delegation revoke$`,
		theDelegatedRegisteredIdentityIsNotAllowedForAuthenticationOnTheDocumentAfterDelegationRevoke)
	suite.AddStep(`^the controller is allowed for control and authentication$`, theControllerIsAllowedForControlAndAuthentication)
	suite.AddStep(`^the "(agent|twin|user)" document is updated with the new name$`, theIdentityTypeDocumentIsUpdatedWithTheNewName)
	suite.AddStep(`^the identity is valid$`, theIdentityIsValid)
	suite.AddStep(`^the "(twin|user)" document is updated with the agent authentication delegation$`,
		theDocumentIsUpdatedWithTheAgentAuthenticationDelegation)
	suite.AddStep(`^the document is updated with the new "(controller|creator)"$`, theDocumentIsUpdatedWithTheNewAttribute)
	suite.AddStep(`^the document is revoked$`, theDocumentIsRevoked)
	suite.AddStep(`^the corresponding document is returned$`, theCorrespondingDocumentIsReturned)
	suite.AddStep(`^the document is valid$`, theDocumentIsValid)
	suite.AddStep(`^a validation error is raised$`, aValidationErrorIsRaised)
	suite.AddStep(`^the token "is( not)?" authorized for authentication$`, theTokenIsOrIsNotAuthorizedForAuthentication)
	suite.AddStep(`^the new owner key has been added to the document$`, theNewOwnerKeyHasBeenAddedToTheDocument)
	suite.AddStep(`^the key has been removed from the document$`, theKeyHasBeenRemovedFromTheDocument)

	suite.Run()
}
