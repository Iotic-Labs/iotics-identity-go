// Copyright (c) IOTIC LABS LIMITED. All rights reserved. Licensed under the Apache License, Version 2.0.

package advancedapi_test

import (
	"strings"
	"testing"
	"time"

	"github.com/Iotic-Labs/iotics-identity-go/pkg/advancedapi"
	"github.com/Iotic-Labs/iotics-identity-go/pkg/crypto"
	"github.com/Iotic-Labs/iotics-identity-go/pkg/identity"
	"github.com/Iotic-Labs/iotics-identity-go/pkg/register"
	"github.com/Iotic-Labs/iotics-identity-go/pkg/test"
	"gotest.tools/assert"
)

func Test_get_key_pair_from_hex_private_key(t *testing.T) {
	privateExponent := strings.Repeat("a", 64)
	expectedBase58 := "PbNnn5VGAkos1X5gcduURAAj4J6e3Awe7Wy45TbKS1SNMTHTBsAG4pvJSfx7ui22zXKzdasQ3ym4idkD5b8YTwYh"
	keypair, err := advancedapi.GetKeyPairFromPrivateExponentHex(privateExponent)
	assert.NilError(t, err)
	assert.Equal(t, keypair.PublicKeyBase58, expectedBase58)
}

func Test_get_key_pair_from_hex_private_key_error(t *testing.T) {
	_, err := advancedapi.GetKeyPairFromPrivateExponentHex("")
	assert.ErrorContains(t, err, "invalid length, need 256 bits")
}

func Test_get_issuer_by_public_key_raises_not_found_error_if_not_found(t *testing.T) {
	subjectDoc, _ := test.HelperGetRegisterDocumentFromSecret(test.ValidKeyPairPlop, "#name", identity.User)
	_, err := advancedapi.GetIssuerByPublicKey(subjectDoc, test.ValidKeyPairPlop2.PublicKeyBase58)
	assert.ErrorContains(t, err, "issuer not found")
}

func Test_can_get_delegation_proof(t *testing.T) {
	subjectDoc, _ := test.HelperGetRegisterDocumentFromSecret(test.ValidKeyPairPlop, "#name", identity.User)
	delegatingIssuer, _ := register.NewIssuer("did:iotics:iotXarXAbViugciWyuFmwRTbNoB6y8Wievfn", "#user-0")

	issuer, proof, err := advancedapi.CreateDelegationProof(delegatingIssuer, subjectDoc, test.ValidKeyPairPlop)
	assert.NilError(t, err)
	assert.Equal(t, issuer.Did, subjectDoc.ID)
	assert.DeepEqual(t, proof.Content, []byte(delegatingIssuer.Did))
}

func Test_cannot_get_delegation_proof(t *testing.T) {
	subjectDoc, subjectIssuer := test.HelperGetRegisterDocumentFromSecret(test.ValidKeyPairPlop, "#name", identity.User)
	delegatingIssuer, err := register.NewIssuer("did:iotics:iotXarXAbViugciWyuFmwRTbNoB6y8Wievfn", "#user-0")
	assert.NilError(t, err)

	subjectIdentity := register.NewRegisteredIdentity(test.ValidKeyPairPlop, subjectIssuer)

	resolver := test.NewInMemoryResolver()
	err = advancedapi.RegisterUpdatedDocument(resolver, subjectDoc, test.ValidKeyPairPlop, subjectIssuer)
	assert.NilError(t, err)

	// Create and add second key to document so original key can be removed
	secondKey, err := crypto.GetPrivateKeyFromExponent("baddbaddbaddbaddbaddbaddbaddbaddbaddbaddbaddbaddbaddbaddbaddbadd")
	assert.NilError(t, err)
	_, secondKeyPublicBase58, err := crypto.GetPublicKeysFromPrivateKey(secondKey)
	assert.NilError(t, err)
	err = advancedapi.AddPublicKeyToDocument(resolver, "#second", secondKeyPublicBase58, subjectIdentity)
	assert.NilError(t, err)

	err = advancedapi.RemovePublicKeyFromDocument(resolver, "#name", subjectIdentity)
	assert.NilError(t, err)

	subjectDoc, err = resolver.GetDocument(subjectDoc.ID)
	assert.NilError(t, err)

	_, _, err = advancedapi.CreateDelegationProof(delegatingIssuer, subjectDoc, test.ValidKeyPairPlop)
	assert.ErrorContains(t, err, "unable to find public key in document matching key pair secrets")
}

func Test_can_get_document_if_exists(t *testing.T) {
	subjectDoc, _ := test.HelperGetRegisterDocumentFromSecret(test.ValidKeyPairPlop, "#name", identity.User)
	resolver := test.NewInMemoryResolver(subjectDoc)
	doc, err := resolver.GetDocument(subjectDoc.ID)
	assert.NilError(t, err)
	assert.DeepEqual(t, subjectDoc, doc)
}

func Test_can_register_a_doc(t *testing.T) {
	subjectDoc, _ := test.HelperGetRegisterDocumentFromSecret(test.ValidKeyPairPlop, "#name", identity.User)
	issuer, err := register.NewIssuer(subjectDoc.ID, "#name")
	assert.NilError(t, err)

	resolver := test.NewInMemoryResolver()
	err = resolver.RegisterDocument(subjectDoc, test.ValidKeyPairPlop.PrivateKey, issuer)
	assert.NilError(t, err)
}

func Test_can_create_new_registered_identity(t *testing.T) {
	resolver := test.NewInMemoryResolver()
	regID, err := advancedapi.NewRegisteredIdentity(resolver, identity.User, test.ValidKeyPairPlop, "#NewId", false)
	assert.NilError(t, err)
	assert.DeepEqual(t, regID.KeyPair(), test.ValidKeyPairPlop)
	assert.Equal(t, regID.Issuer().Name, "#NewId")

	assert.Assert(t, regDoc != nil)
	assert.Assert(t, regDoc.ID == regID.Did()) //nolint:staticcheck

	_, err = resolver.GetDocument(regID.Did())
	assert.NilError(t, err)
}

func Test_can_create_new_registered_identity_with_default_issuer_name(t *testing.T) {
	cases := []struct {
		purpose identity.DidType
		name    string
	}{
		{identity.Agent, "#agent-0"},
		{identity.User, "#user-0"},
		{identity.Host, "#host-0"},
		{identity.Twin, "#twin-0"},
	}
	for _, c := range cases {
		resolver := test.NewInMemoryResolver()
		regID, err := advancedapi.NewRegisteredIdentity(resolver, c.purpose, test.ValidKeyPairPlop, "", false)
		assert.NilError(t, err)
		assert.DeepEqual(t, regID.KeyPair(), test.ValidKeyPairPlop)
		assert.Equal(t, regID.Issuer().Name, c.name)
	}
}

func Test_can_create_new_registered_identity_will_not_override_doc_if_exists(t *testing.T) {
	resolver := test.NewInMemoryResolver()
	regID, err := advancedapi.NewRegisteredIdentity(resolver, identity.User, test.ValidKeyPairPlop, "#ExistingId", false)
	assert.NilError(t, err)

	doc, err := resolver.GetDocument(regID.Did())
	assert.NilError(t, err)
	assert.Check(t, len(doc.PublicKeys) == 1)
	assert.Check(t, doc.PublicKeys[0].ID == "#ExistingId")

	regID, err = advancedapi.NewRegisteredIdentity(resolver, identity.User, test.ValidKeyPairPlop, "#NewId", false)
	assert.NilError(t, err)

	doc, err = resolver.GetDocument(regID.Did())
	assert.NilError(t, err)
	assert.Check(t, len(doc.PublicKeys) == 1)
	assert.Check(t, doc.PublicKeys[0].ID == "#ExistingId")
}

func Test_can_create_new_registered_identity_will_override_doc_if_exists_and_override_true(t *testing.T) {
	resolver := test.NewInMemoryResolver()
	regID, err := advancedapi.NewRegisteredIdentity(resolver, identity.User, test.ValidKeyPairPlop, "#ExistingId", false)
	assert.NilError(t, err)

	doc, err := resolver.GetDocument(regID.Did())
	assert.NilError(t, err)
	assert.Check(t, len(doc.PublicKeys) == 1)
	assert.Check(t, doc.PublicKeys[0].ID == "#ExistingId")

	regID, err = advancedapi.NewRegisteredIdentity(resolver, identity.User, test.ValidKeyPairPlop, "#NewId", true)
	assert.NilError(t, err)

	doc, err = resolver.GetDocument(regID.Did())
	assert.NilError(t, err)
	assert.Check(t, len(doc.PublicKeys) == 1)
	assert.Check(t, doc.PublicKeys[0].ID == "#NewId")
}

func Test_can_delegate_authentication(t *testing.T) {
	resolver := test.NewInMemoryResolver()
	userID, err := advancedapi.NewRegisteredIdentity(resolver, identity.User, test.ValidKeyPairPlop, "#ExistingId", false)
	assert.NilError(t, err)
	agentID, err := advancedapi.NewRegisteredIdentity(resolver, identity.User, test.ValidKeyPairPlop2, "#ExistingId", false)
	assert.NilError(t, err)

	err = advancedapi.DelegateAuthentication(resolver, userID.KeyPair(), userID.Did(), agentID.KeyPair(), agentID.Did(), test.DelegationName)
	assert.NilError(t, err)

	doc, err := resolver.GetDocument(userID.Did())
	assert.NilError(t, err)

	assert.Check(t, len(doc.DelegateAuthentication) == 1)
	assert.Check(t, doc.DelegateAuthentication[0].ID == test.DelegationName)
	assert.Check(t, doc.DelegateAuthentication[0].Controller == agentID.Issuer().String())
	assert.Check(t, doc.DelegateAuthentication[0].Revoked == false)
	assert.Check(t, len(doc.DelegateAuthentication[0].Proof) > 0)
}

func Test_can_delegate_control(t *testing.T) {
	resolver := test.NewInMemoryResolver()
	twinID, err := advancedapi.NewRegisteredIdentity(resolver, identity.Twin, test.ValidKeyPairPlop, "#ExistingId", false)
	assert.NilError(t, err)
	agentID, err := advancedapi.NewRegisteredIdentity(resolver, identity.User, test.ValidKeyPairPlop2, "#ExistingId", false)
	assert.NilError(t, err)

	err = advancedapi.DelegateControl(resolver, twinID.KeyPair(), twinID.Did(), agentID.KeyPair(), agentID.Did(), "#NewDelegCtrl")
	assert.NilError(t, err)

	doc, err := resolver.GetDocument(twinID.Did())
	assert.NilError(t, err)

	assert.Check(t, len(doc.DelegateControl) == 1)
	assert.Check(t, doc.DelegateControl[0].ID == "#NewDelegCtrl")
	assert.Check(t, doc.DelegateControl[0].Controller == agentID.Issuer().String())
	assert.Check(t, doc.DelegateControl[0].Revoked == false)
	// assert.Check(t, len(doc.DelegateControl[0].Proof))
}

func Test_can_add_public_key_to_a_document(t *testing.T) {
	resolver := test.NewInMemoryResolver()
	twinID, err := advancedapi.NewRegisteredIdentity(resolver, identity.Twin, test.ValidKeyPairPlop, "#ExistingId", false)
	assert.NilError(t, err)

	err = advancedapi.AddPublicKeyToDocument(resolver, "#NewOwner", test.ValidKeyPairPlop2.PublicKeyBase58, twinID)
	assert.NilError(t, err)

	doc, err := resolver.GetDocument(twinID.Did())
	assert.NilError(t, err)

	found := false
	assert.Check(t, len(doc.PublicKeys) == 2)
	for _, v := range doc.PublicKeys {
		if v.ID == "#NewOwner" {
			found = true
			assert.Check(t, v.PublicKeyBase58 == test.ValidKeyPairPlop2.PublicKeyBase58)
			assert.Check(t, v.Revoked == false)
		}
	}
	assert.Check(t, found)
}

func Test_can_add_auth_key_to_a_document(t *testing.T) {
	resolver := test.NewInMemoryResolver()
	twinID, err := advancedapi.NewRegisteredIdentity(resolver, identity.Twin, test.ValidKeyPairPlop, "#ExistingId", false)
	assert.NilError(t, err)

	err = advancedapi.AddAuthenticationKeyToDocument(resolver, "#NewAuth", test.ValidKeyPairPlop2.PublicKeyBase58, twinID)
	assert.NilError(t, err)

	doc, err := resolver.GetDocument(twinID.Did())
	assert.NilError(t, err)

	assert.Check(t, len(doc.AuthenticationKeys) == 1)
	assert.Check(t, doc.AuthenticationKeys[0].ID == "#NewAuth")
	assert.Check(t, doc.AuthenticationKeys[0].PublicKeyBase58 == test.ValidKeyPairPlop2.PublicKeyBase58)
	assert.Check(t, doc.AuthenticationKeys[0].Revoked == false)
}

func Test_can_add_auth_delegation_proof(t *testing.T) {
	resolver := test.NewInMemoryResolver()
	twinID, err := advancedapi.NewRegisteredIdentity(resolver, identity.Twin, test.ValidKeyPairPlop, "#ExistingId", false)
	assert.NilError(t, err)

	err = advancedapi.AddAuthenticationDelegationToDocument(resolver, test.OtherDelegationName, test.OtherDocIssuer.String(), test.OtherProof, twinID)
	assert.NilError(t, err)

	doc, err := resolver.GetDocument(twinID.Did())
	assert.NilError(t, err)

	assert.Check(t, doc.DelegateAuthentication[0].ID == "#newDeleg")
	assert.Check(t, doc.DelegateAuthentication[0].Controller == test.OtherDocIssuer.String())
	assert.Check(t, doc.DelegateAuthentication[0].Proof == test.OtherProof)
	assert.Check(t, doc.DelegateAuthentication[0].Revoked == false)
}

func Test_can_add_control_delegation_proof(t *testing.T) {
	resolver := test.NewInMemoryResolver()
	twinID, err := advancedapi.NewRegisteredIdentity(resolver, identity.Twin, test.ValidKeyPairPlop, "#ExistingId", false)
	assert.NilError(t, err)

	err = advancedapi.AddControlDelegationToDocument(resolver, "#newDeleg", test.OtherDocIssuer.String(), test.OtherProof, twinID)
	assert.NilError(t, err)

	doc, err := resolver.GetDocument(twinID.Did())
	assert.NilError(t, err)

	assert.Check(t, doc.DelegateControl[0].ID == "#newDeleg")
	assert.Check(t, doc.DelegateControl[0].Controller == test.OtherDocIssuer.String())
	assert.Check(t, doc.DelegateControl[0].Proof == test.OtherProof)
	assert.Check(t, doc.DelegateControl[0].Revoked == false)
}

func Test_can_remove_control_delegation(t *testing.T) {
	resolver := test.NewInMemoryResolver()
	twinID, err := advancedapi.NewRegisteredIdentity(resolver, identity.Twin, test.ValidKeyPairPlop, "#ExistingId", false)
	assert.NilError(t, err)

	err = advancedapi.AddControlDelegationToDocument(resolver, "#newDeleg", test.OtherDocIssuer.String(), test.OtherProof, twinID)
	assert.NilError(t, err)

	doc, err := resolver.GetDocument(twinID.Did())
	assert.NilError(t, err)
	assert.Check(t, len(doc.DelegateControl) == 1)

	err = advancedapi.RemoveControlDelegationFromDocument(resolver, "#newDeleg", twinID)
	assert.NilError(t, err)

	doc, err = resolver.GetDocument(twinID.Did())
	assert.NilError(t, err)
	assert.Check(t, len(doc.DelegateControl) == 0)
}

func Test_can_remove_auth_delegation(t *testing.T) {
	resolver := test.NewInMemoryResolver()
	twinID, err := advancedapi.NewRegisteredIdentity(resolver, identity.Twin, test.ValidKeyPairPlop, "#ExistingId", false)
	assert.NilError(t, err)

	err = advancedapi.AddAuthenticationDelegationToDocument(resolver, "#newDeleg", test.OtherDocIssuer.String(), test.OtherProof, twinID)
	assert.NilError(t, err)

	doc, err := resolver.GetDocument(twinID.Did())
	assert.NilError(t, err)
	assert.Check(t, len(doc.DelegateAuthentication) == 1)

	err = advancedapi.RemoveAuthenticationDelegationFromDocument(resolver, "#newDeleg", twinID)
	assert.NilError(t, err)

	doc, err = resolver.GetDocument(twinID.Did())
	assert.NilError(t, err)
	assert.Check(t, len(doc.DelegateAuthentication) == 0)
}

func Test_can_revoke_control_delegation(t *testing.T) {
	resolver := test.NewInMemoryResolver()
	twinID, err := advancedapi.NewRegisteredIdentity(resolver, identity.Twin, test.ValidKeyPairPlop, "#ExistingId", false)
	assert.NilError(t, err)

	err = advancedapi.AddControlDelegationToDocument(resolver, "#newDeleg", test.OtherDocIssuer.String(), test.OtherProof, twinID)
	assert.NilError(t, err)

	doc, err := resolver.GetDocument(twinID.Did())
	assert.NilError(t, err)
	assert.Check(t, doc.DelegateControl[0].Revoked == false)

	err = advancedapi.RevokeControlDelegationFromDocument(resolver, "#newDeleg", twinID)
	assert.NilError(t, err)

	doc, err = resolver.GetDocument(twinID.Did())
	assert.NilError(t, err)
	assert.Check(t, len(doc.DelegateControl) == 1)
	assert.Check(t, doc.DelegateControl[0].Revoked == true)
}

func Test_can_revoke_auth_delegation(t *testing.T) {
	resolver := test.NewInMemoryResolver()
	twinID, err := advancedapi.NewRegisteredIdentity(resolver, identity.Twin, test.ValidKeyPairPlop, "#ExistingId", false)
	assert.NilError(t, err)

	err = advancedapi.AddAuthenticationDelegationToDocument(resolver, "#newDeleg", test.OtherDocIssuer.String(), test.OtherProof, twinID)
	assert.NilError(t, err)

	doc, err := resolver.GetDocument(twinID.Did())
	assert.NilError(t, err)
	assert.Check(t, len(doc.DelegateAuthentication) == 1)

	err = advancedapi.RevokeAuthenticationDelegationFromDocument(resolver, "#newDeleg", twinID)
	assert.NilError(t, err)

	doc, err = resolver.GetDocument(twinID.Did())
	assert.NilError(t, err)
	assert.Check(t, len(doc.DelegateAuthentication) == 1)
	assert.Check(t, doc.DelegateAuthentication[0].Revoked == true)
}

func Test_can_validate_document(t *testing.T) {
	resolver := test.NewInMemoryResolver()
	twinID, err := advancedapi.NewRegisteredIdentity(resolver, identity.Twin, test.ValidKeyPairPlop, "#ExistingId", false)
	assert.NilError(t, err)

	otherId, err := advancedapi.NewRegisteredIdentity(resolver, identity.Agent, test.ValidKeyPairPlop2, "#otherId", false)
	assert.NilError(t, err)

	otherDoc, _ := resolver.GetDocument(otherId.Did())
	_, proof, err := advancedapi.CreateDelegationProof(twinID.Issuer(), otherDoc, test.ValidKeyPairPlop2)
	assert.NilError(t, err)

	err = advancedapi.AddControlDelegationToDocument(resolver, "#newDelegCtrl", otherId.Issuer().String(), proof.Signature, twinID)
	assert.NilError(t, err)

	err = advancedapi.AddAuthenticationDelegationToDocument(resolver, "#newDeleg", otherId.Issuer().String(), proof.Signature, twinID)
	assert.NilError(t, err)

	doc, err := resolver.GetDocument(twinID.Did())
	assert.NilError(t, err)
	assert.Check(t, len(doc.DelegateAuthentication) == 1)
	assert.Check(t, len(doc.DelegateControl) == 1)

	err = advancedapi.ValidateRegisterDocument(resolver, doc)
	assert.NilError(t, err)
}

func Test_can_validate_document_delegations(t *testing.T) {
	resolver := test.NewInMemoryResolver()
	agentID, err := advancedapi.NewRegisteredIdentity(resolver, identity.Agent, test.ValidKeyPairPlop, "#agent", false)
	assert.NilError(t, err)
	userID, err := advancedapi.NewRegisteredIdentity(resolver, identity.User, test.ValidKeyPairPlop2, "#user", false)
	assert.NilError(t, err)

	agentDoc, _ := resolver.GetDocument(agentID.Did())
	_, proof, err := advancedapi.CreateDelegationProof(userID.Issuer(), agentDoc, agentID.KeyPair())
	assert.NilError(t, err)

	err = advancedapi.AddAuthenticationDelegationToDocument(resolver, "#deleg", agentID.Issuer().String(), proof.Signature, userID)
	assert.NilError(t, err)

	err = advancedapi.ValidateRegisterDocument(resolver, agentDoc)
	assert.NilError(t, err)

	userDoc, _ := resolver.GetDocument(userID.Did())
	err = advancedapi.ValidateRegisterDocument(resolver, userDoc)
	assert.NilError(t, err)

	userDoc.DelegateAuthentication[0].Proof = "aGVsbG8gd29ybGQ=" // hello world
	err = advancedapi.ValidateRegisterDocument(resolver, userDoc)
	assert.ErrorContains(t, err, "unable to decode proof signature")
}

func Test_can_set_document_controller(t *testing.T) {
	resolver := test.NewInMemoryResolver()
	twinID, err := advancedapi.NewRegisteredIdentity(resolver, identity.Twin, test.ValidKeyPairPlop, "#ExistingId", false)
	assert.NilError(t, err)

	initialDoc, err := resolver.GetDocument(twinID.Did())
	assert.NilError(t, err)

	time.Sleep(time.Millisecond) // Note: Need to sleep to ensure UpdateTime is updated on document build
	err = advancedapi.SetDocumentController(resolver, twinID, test.ValidIssuer)
	assert.NilError(t, err)

	updatedDoc, err := resolver.GetDocument(twinID.Did())
	assert.NilError(t, err)
	assert.Check(t, updatedDoc.Controller == test.ValidIssuer.Did)
	assert.Check(t, updatedDoc.UpdateTime > initialDoc.UpdateTime)
}

func Test_can_set_document_creator(t *testing.T) {
	resolver := test.NewInMemoryResolver()
	twinID, err := advancedapi.NewRegisteredIdentity(resolver, identity.Twin, test.ValidKeyPairPlop, "#ExistingId", false)
	assert.NilError(t, err)

	err = advancedapi.SetDocumentCreator(resolver, twinID, test.OtherDocIssuer)
	assert.NilError(t, err)

	doc, err := resolver.GetDocument(twinID.Did())
	assert.NilError(t, err)
	assert.Check(t, doc.Creator == test.OtherDocIssuer.Did)
}

func Test_can_set_document_revoked(t *testing.T) {
	resolver := test.NewInMemoryResolver()
	twinID, err := advancedapi.NewRegisteredIdentity(resolver, identity.Twin, test.ValidKeyPairPlop, "#ExistingId", false)
	assert.NilError(t, err)

	err = advancedapi.SetDocumentRevoked(resolver, twinID, true)
	assert.NilError(t, err)

	doc, err := resolver.GetDocument(twinID.Did())
	assert.NilError(t, err)
	assert.Check(t, doc.Revoked == true)
}

func Test_can_remove_public_key(t *testing.T) {
	resolver := test.NewInMemoryResolver()
	twinID, err := advancedapi.NewRegisteredIdentity(resolver, identity.Twin, test.ValidKeyPairPlop, "#ExistingId", false)
	assert.NilError(t, err)

	err = advancedapi.AddPublicKeyToDocument(resolver, "#NewPub", test.ValidKeyPairPlop2.PublicKeyBase58, twinID)
	assert.NilError(t, err)

	err = advancedapi.RemovePublicKeyFromDocument(resolver, "#NewPub", twinID)
	assert.NilError(t, err)

	doc, err := resolver.GetDocument(twinID.Did())
	assert.NilError(t, err)

	assert.Check(t, len(doc.PublicKeys) == 1)
}

func Test_can_revoke_public_key(t *testing.T) {
	resolver := test.NewInMemoryResolver()
	twinID, err := advancedapi.NewRegisteredIdentity(resolver, identity.Twin, test.ValidKeyPairPlop, "#ExistingId", false)
	assert.NilError(t, err)

	err = advancedapi.RevokePublicKeyFromDocument(resolver, twinID.Issuer().Name, twinID)
	assert.NilError(t, err)

	doc, err := resolver.GetDocument(twinID.Did())
	assert.NilError(t, err)

	assert.Check(t, len(doc.PublicKeys) == 1)
	assert.Check(t, doc.PublicKeys[0].Revoked == true)
}

func Test_can_remove_auth_key(t *testing.T) {
	resolver := test.NewInMemoryResolver()
	twinID, err := advancedapi.NewRegisteredIdentity(resolver, identity.Twin, test.ValidKeyPairPlop, "#ExistingId", false)
	assert.NilError(t, err)

	err = advancedapi.AddAuthenticationKeyToDocument(resolver, "#NewAuth", test.ValidKeyPairPlop2.PublicKeyBase58, twinID)
	assert.NilError(t, err)

	err = advancedapi.RemoveAuthenticationKeyFromDocument(resolver, "#NewAuth", twinID)
	assert.NilError(t, err)

	doc, err := resolver.GetDocument(twinID.Did())
	assert.NilError(t, err)

	assert.Check(t, len(doc.AuthenticationKeys) == 0)
}

func Test_can_revoke_auth_key(t *testing.T) {
	resolver := test.NewInMemoryResolver()
	twinID, err := advancedapi.NewRegisteredIdentity(resolver, identity.Twin, test.ValidKeyPairPlop, "#ExistingId", false)
	assert.NilError(t, err)

	err = advancedapi.AddAuthenticationKeyToDocument(resolver, "#NewAuth", test.ValidKeyPairPlop2.PublicKeyBase58, twinID)
	assert.NilError(t, err)

	err = advancedapi.RevokeAuthenticationKeyFromDocument(resolver, "#NewAuth", twinID)
	assert.NilError(t, err)

	doc, err := resolver.GetDocument(twinID.Did())
	assert.NilError(t, err)

	assert.Check(t, len(doc.AuthenticationKeys) == 1)
	assert.Check(t, doc.AuthenticationKeys[0].Revoked == true)
}

func Test_can_create_agent_auth_token(t *testing.T) {
	resolver := test.NewInMemoryResolver()
	agentID, err := advancedapi.NewRegisteredIdentity(resolver, identity.Agent, test.ValidKeyPairPlop, "#agent", false)
	assert.NilError(t, err)
	userID, err := advancedapi.NewRegisteredIdentity(resolver, identity.User, test.ValidKeyPairPlop2, "#user", false)
	assert.NilError(t, err)

	agentDoc, _ := resolver.GetDocument(agentID.Did())
	_, proof, err := advancedapi.CreateDelegationProof(userID.Issuer(), agentDoc, agentID.KeyPair())
	assert.NilError(t, err)

	err = advancedapi.AddAuthenticationDelegationToDocument(resolver, "#deleg", agentID.Issuer().String(), proof.Signature, userID)
	assert.NilError(t, err)

	duration, _ := time.ParseDuration("10s")
	token, err := advancedapi.CreateAgentAuthToken(agentID, userID.Did(), duration, "audience", 0)
	assert.NilError(t, err)
	assert.Check(t, len(string(token)) > 0)
}

func Test_can_create_twin_auth_token(t *testing.T) {
	resolver := test.NewInMemoryResolver()
	twinID, err := advancedapi.NewRegisteredIdentity(resolver, identity.Twin, test.ValidKeyPairPlop2, "#twin", false)
	assert.NilError(t, err)

	duration, _ := time.ParseDuration("10s")
	token, err := advancedapi.CreateTwinAuthToken(twinID, duration, "audience", 01)
	assert.NilError(t, err)
	assert.Check(t, len(string(token)) > 0)
}

func Test_can_create_identifier(t *testing.T) {
	id, err := advancedapi.CreateIdentifier(test.ValidKeyPairPlop.PublicKeyBytes)
	assert.NilError(t, err)
	assert.Check(t, id == "did:iotics:iotFqH94g4jG58XNMDK9k5YCmQgcpNPUhWFx")
}

func Test_can_validate_document_proof(t *testing.T) {
	resolver := test.NewInMemoryResolver()
	twinID, err := advancedapi.NewRegisteredIdentity(resolver, identity.Twin, test.ValidKeyPairPlop, "#ExistingId", false)
	assert.NilError(t, err)

	doc, err := resolver.GetDocument(twinID.Did())
	assert.NilError(t, err)

	err = advancedapi.ValidateDocumentProof(doc)
	assert.NilError(t, err)
}

func Test_cannot_validate_document_proof(t *testing.T) {
	resolver := test.NewInMemoryResolver()
	twinID, err := advancedapi.NewRegisteredIdentity(resolver, identity.Twin, test.ValidKeyPairPlop, "#ExistingId", false)
	assert.NilError(t, err)

	// Create and add second key to document so original key can be removed
	secondKey, err := crypto.GetPrivateKeyFromExponent("baddbaddbaddbaddbaddbaddbaddbaddbaddbaddbaddbaddbaddbaddbaddbadd")
	assert.NilError(t, err)
	_, secondKeyPublicBase58, err := crypto.GetPublicKeysFromPrivateKey(secondKey)
	assert.NilError(t, err)
	err = advancedapi.AddPublicKeyToDocument(resolver, "#second", secondKeyPublicBase58, twinID)
	assert.NilError(t, err)

	err = advancedapi.RemovePublicKeyFromDocument(resolver, "#ExistingId", twinID)
	assert.NilError(t, err)

	doc, err := resolver.GetDocument(twinID.Did())
	assert.NilError(t, err)

	err = advancedapi.ValidateDocumentProof(doc)
	assert.ErrorContains(t, err, "unable to find public key matching document ID")
}

func Test_can_create_seed(t *testing.T) {
	seed, err := advancedapi.CreateSeed(128)
	assert.NilError(t, err)
	assert.Check(t, len(seed) == 16)

	seed, err = advancedapi.CreateSeed(256)
	assert.NilError(t, err)
	assert.Check(t, len(seed) == 32)

	_, err = advancedapi.CreateSeed(384)
	assert.ErrorContains(t, err, "length must be 128 or 256")
}
