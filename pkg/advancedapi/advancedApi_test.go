// Copyright (c) IOTIC LABS LIMITED. All rights reserved. Licensed under the Apache License, Version 2.0.

package advancedapi_test

import (
	"strings"
	"testing"
	"time"

	advancedapi2 "github.com/Iotic-Labs/iotics-identity-go/pkg/advancedapi"
	"github.com/Iotic-Labs/iotics-identity-go/pkg/identity"
	"github.com/Iotic-Labs/iotics-identity-go/pkg/register"
	"github.com/Iotic-Labs/iotics-identity-go/pkg/test"
	"gotest.tools/assert"
)

func Test_get_key_pair_from_hex_private_key(t *testing.T) {
	privateExponent := strings.Repeat("a", 64)
	expectedBase58 := "PbNnn5VGAkos1X5gcduURAAj4J6e3Awe7Wy45TbKS1SNMTHTBsAG4pvJSfx7ui22zXKzdasQ3ym4idkD5b8YTwYh"
	keypair, err := advancedapi2.GetKeyPairFromPrivateExponentHex(privateExponent)
	assert.NilError(t, err)
	assert.Equal(t, keypair.PublicKeyBase58, expectedBase58)
}

func Test_get_key_pair_from_hex_private_key_error(t *testing.T) {
	_, err := advancedapi2.GetKeyPairFromPrivateExponentHex("")
	assert.ErrorContains(t, err, "invalid length, need 256 bits")
}

func Test_get_issuer_by_public_key_raises_not_found_error_if_not_found(t *testing.T) {
	subjectDoc, _ := test.HelperGetRegisterDocumentFromSecret(test.ValidKeyPairPlop, "#name", identity.User)
	_, err := advancedapi2.GetIssuerByPublicKey(subjectDoc, test.ValidKeyPairPlop2.PublicKeyBase58)
	assert.ErrorContains(t, err, "issuer not found")
}

func Test_can_get_delegation_proof(t *testing.T) {
	subjectDoc, _ := test.HelperGetRegisterDocumentFromSecret(test.ValidKeyPairPlop, "#name", identity.User)
	delegatingIssuer, _ := register.NewIssuer("did:iotics:iotXarXAbViugciWyuFmwRTbNoB6y8Wievfn", "#user-0")

	issuer, proof, err := advancedapi2.CreateDelegationProof(delegatingIssuer, subjectDoc, test.ValidKeyPairPlop)
	assert.NilError(t, err)
	assert.Equal(t, issuer.Did, subjectDoc.ID)
	assert.DeepEqual(t, proof.Content, []byte(delegatingIssuer.Did))
}

func Test_cannot_get_delegation_proof(t *testing.T) {
	subjectDoc, subjectIssuer := test.HelperGetRegisterDocumentFromSecret(test.ValidKeyPairPlop, "#name", identity.User)
	delegatingIssuer, _ := register.NewIssuer("did:iotics:iotXarXAbViugciWyuFmwRTbNoB6y8Wievfn", "#user-0")

	subjectIdentity := register.NewRegisteredIdentity(test.ValidKeyPairPlop, subjectIssuer)

	resolver := test.NewInMemoryResolver()
	_ = advancedapi2.RegisterUpdatedDocument(resolver, subjectDoc, test.ValidKeyPairPlop, subjectIssuer)
	_ = advancedapi2.RemovePublicKeyFromDocument(resolver, "#name", subjectIdentity)
	subjectDoc, _ = resolver.GetDocument(subjectDoc.ID)

	_, _, err := advancedapi2.CreateDelegationProof(delegatingIssuer, subjectDoc, test.ValidKeyPairPlop)
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
	regId, err := advancedapi2.NewRegisteredIdentity(resolver, identity.User, test.ValidKeyPairPlop, "#NewId", false)
	assert.NilError(t, err)
	assert.DeepEqual(t, regId.KeyPair(), test.ValidKeyPairPlop)
	assert.Equal(t, regId.Issuer().Name, "#NewId")

	_, err = resolver.GetDocument(regId.Did())
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
		regId, err := advancedapi2.NewRegisteredIdentity(resolver, c.purpose, test.ValidKeyPairPlop, "", false)
		assert.NilError(t, err)
		assert.DeepEqual(t, regId.KeyPair(), test.ValidKeyPairPlop)
		assert.Equal(t, regId.Issuer().Name, c.name)
	}
}

func Test_can_create_new_registered_identity_will_not_override_doc_if_exists(t *testing.T) {
	resolver := test.NewInMemoryResolver()
	regId, err := advancedapi2.NewRegisteredIdentity(resolver, identity.User, test.ValidKeyPairPlop, "#ExistingId", false)
	assert.NilError(t, err)

	doc, err := resolver.GetDocument(regId.Did())
	assert.NilError(t, err)
	assert.Check(t, len(doc.PublicKeys) == 1)
	assert.Check(t, doc.PublicKeys[0].ID == "#ExistingId")

	regId, err = advancedapi2.NewRegisteredIdentity(resolver, identity.User, test.ValidKeyPairPlop, "#NewId", false)
	assert.NilError(t, err)

	doc, err = resolver.GetDocument(regId.Did())
	assert.NilError(t, err)
	assert.Check(t, len(doc.PublicKeys) == 1)
	assert.Check(t, doc.PublicKeys[0].ID == "#ExistingId")
}

func Test_can_create_new_registered_identity_will_override_doc_if_exists_and_override_true(t *testing.T) {
	resolver := test.NewInMemoryResolver()
	regId, err := advancedapi2.NewRegisteredIdentity(resolver, identity.User, test.ValidKeyPairPlop, "#ExistingId", false)
	assert.NilError(t, err)

	doc, err := resolver.GetDocument(regId.Did())
	assert.NilError(t, err)
	assert.Check(t, len(doc.PublicKeys) == 1)
	assert.Check(t, doc.PublicKeys[0].ID == "#ExistingId")

	regId, err = advancedapi2.NewRegisteredIdentity(resolver, identity.User, test.ValidKeyPairPlop, "#NewId", true)
	assert.NilError(t, err)

	doc, err = resolver.GetDocument(regId.Did())
	assert.NilError(t, err)
	assert.Check(t, len(doc.PublicKeys) == 1)
	assert.Check(t, doc.PublicKeys[0].ID == "#NewId")
}

func Test_can_delegate_authentication(t *testing.T) {
	resolver := test.NewInMemoryResolver()
	userId, err := advancedapi2.NewRegisteredIdentity(resolver, identity.User, test.ValidKeyPairPlop, "#ExistingId", false)
	assert.NilError(t, err)
	agentId, err := advancedapi2.NewRegisteredIdentity(resolver, identity.User, test.ValidKeyPairPlop2, "#ExistingId", false)
	assert.NilError(t, err)

	err = advancedapi2.DelegateAuthentication(resolver, userId.KeyPair(), userId.Did(), agentId.KeyPair(), agentId.Did(), test.DelegationName)
	assert.NilError(t, err)

	doc, err := resolver.GetDocument(userId.Did())
	assert.NilError(t, err)

	assert.Check(t, len(doc.DelegateAuthentication) == 1)
	assert.Check(t, doc.DelegateAuthentication[0].ID == test.DelegationName)
	assert.Check(t, doc.DelegateAuthentication[0].Controller == agentId.Issuer().String())
	assert.Check(t, doc.DelegateAuthentication[0].Revoked == false)
	assert.Check(t, len(doc.DelegateAuthentication[0].Proof) > 0)
}

func Test_can_delegate_control(t *testing.T) {
	resolver := test.NewInMemoryResolver()
	twinId, err := advancedapi2.NewRegisteredIdentity(resolver, identity.Twin, test.ValidKeyPairPlop, "#ExistingId", false)
	assert.NilError(t, err)
	agentId, err := advancedapi2.NewRegisteredIdentity(resolver, identity.User, test.ValidKeyPairPlop2, "#ExistingId", false)
	assert.NilError(t, err)

	err = advancedapi2.DelegateControl(resolver, twinId.KeyPair(), twinId.Did(), agentId.KeyPair(), agentId.Did(), "#NewDelegCtrl")
	assert.NilError(t, err)

	doc, err := resolver.GetDocument(twinId.Did())
	assert.NilError(t, err)

	assert.Check(t, len(doc.DelegateControl) == 1)
	assert.Check(t, doc.DelegateControl[0].ID == "#NewDelegCtrl")
	assert.Check(t, doc.DelegateControl[0].Controller == agentId.Issuer().String())
	assert.Check(t, doc.DelegateControl[0].Revoked == false)
	// assert.Check(t, len(doc.DelegateControl[0].Proof))
}

func Test_can_add_public_key_to_a_document(t *testing.T) {
	resolver := test.NewInMemoryResolver()
	twinId, err := advancedapi2.NewRegisteredIdentity(resolver, identity.Twin, test.ValidKeyPairPlop, "#ExistingId", false)
	assert.NilError(t, err)

	err = advancedapi2.AddPublicKeyToDocument(resolver, "#NewOwner", test.ValidKeyPairPlop2.PublicKeyBase58, twinId)
	assert.NilError(t, err)

	doc, err := resolver.GetDocument(twinId.Did())
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
	twinId, err := advancedapi2.NewRegisteredIdentity(resolver, identity.Twin, test.ValidKeyPairPlop, "#ExistingId", false)
	assert.NilError(t, err)

	err = advancedapi2.AddAuthenticationKeyToDocument(resolver, "#NewAuth", test.ValidKeyPairPlop2.PublicKeyBase58, twinId)
	assert.NilError(t, err)

	doc, err := resolver.GetDocument(twinId.Did())
	assert.NilError(t, err)

	assert.Check(t, len(doc.AuthenticationKeys) == 1)
	assert.Check(t, doc.AuthenticationKeys[0].ID == "#NewAuth")
	assert.Check(t, doc.AuthenticationKeys[0].PublicKeyBase58 == test.ValidKeyPairPlop2.PublicKeyBase58)
	assert.Check(t, doc.AuthenticationKeys[0].Revoked == false)
}

func Test_can_add_auth_delegation_proof(t *testing.T) {
	resolver := test.NewInMemoryResolver()
	twinId, err := advancedapi2.NewRegisteredIdentity(resolver, identity.Twin, test.ValidKeyPairPlop, "#ExistingId", false)
	assert.NilError(t, err)

	err = advancedapi2.AddAuthenticationDelegationToDocument(resolver, test.OtherDelegationName, test.OtherDocIssuer.String(), test.OtherProof, twinId)
	assert.NilError(t, err)

	doc, err := resolver.GetDocument(twinId.Did())
	assert.NilError(t, err)

	assert.Check(t, doc.DelegateAuthentication[0].ID == "#newDeleg")
	assert.Check(t, doc.DelegateAuthentication[0].Controller == test.OtherDocIssuer.String())
	assert.Check(t, doc.DelegateAuthentication[0].Proof == test.OtherProof)
	assert.Check(t, doc.DelegateAuthentication[0].Revoked == false)
}

func Test_can_add_control_delegation_proof(t *testing.T) {
	resolver := test.NewInMemoryResolver()
	twinId, err := advancedapi2.NewRegisteredIdentity(resolver, identity.Twin, test.ValidKeyPairPlop, "#ExistingId", false)
	assert.NilError(t, err)

	err = advancedapi2.AddControlDelegationToDocument(resolver, "#newDeleg", test.OtherDocIssuer.String(), test.OtherProof, twinId)
	assert.NilError(t, err)

	doc, err := resolver.GetDocument(twinId.Did())
	assert.NilError(t, err)

	assert.Check(t, doc.DelegateControl[0].ID == "#newDeleg")
	assert.Check(t, doc.DelegateControl[0].Controller == test.OtherDocIssuer.String())
	assert.Check(t, doc.DelegateControl[0].Proof == test.OtherProof)
	assert.Check(t, doc.DelegateControl[0].Revoked == false)
}

func Test_can_remove_control_delegation(t *testing.T) {
	resolver := test.NewInMemoryResolver()
	twinId, err := advancedapi2.NewRegisteredIdentity(resolver, identity.Twin, test.ValidKeyPairPlop, "#ExistingId", false)
	assert.NilError(t, err)

	err = advancedapi2.AddControlDelegationToDocument(resolver, "#newDeleg", test.OtherDocIssuer.String(), test.OtherProof, twinId)
	assert.NilError(t, err)

	doc, err := resolver.GetDocument(twinId.Did())
	assert.NilError(t, err)
	assert.Check(t, len(doc.DelegateControl) == 1)

	err = advancedapi2.RemoveControlDelegationFromDocument(resolver, "#newDeleg", twinId)

	doc, err = resolver.GetDocument(twinId.Did())
	assert.NilError(t, err)
	assert.Check(t, len(doc.DelegateControl) == 0)
}

func Test_can_remove_auth_delegation(t *testing.T) {
	resolver := test.NewInMemoryResolver()
	twinId, err := advancedapi2.NewRegisteredIdentity(resolver, identity.Twin, test.ValidKeyPairPlop, "#ExistingId", false)
	assert.NilError(t, err)

	err = advancedapi2.AddAuthenticationDelegationToDocument(resolver, "#newDeleg", test.OtherDocIssuer.String(), test.OtherProof, twinId)
	assert.NilError(t, err)

	doc, err := resolver.GetDocument(twinId.Did())
	assert.NilError(t, err)
	assert.Check(t, len(doc.DelegateAuthentication) == 1)

	err = advancedapi2.RemoveAuthenticationDelegationFromDocument(resolver, "#newDeleg", twinId)

	doc, err = resolver.GetDocument(twinId.Did())
	assert.NilError(t, err)
	assert.Check(t, len(doc.DelegateAuthentication) == 0)
}

func Test_can_revoke_control_delegation(t *testing.T) {
	resolver := test.NewInMemoryResolver()
	twinId, err := advancedapi2.NewRegisteredIdentity(resolver, identity.Twin, test.ValidKeyPairPlop, "#ExistingId", false)
	assert.NilError(t, err)

	err = advancedapi2.AddControlDelegationToDocument(resolver, "#newDeleg", test.OtherDocIssuer.String(), test.OtherProof, twinId)
	assert.NilError(t, err)

	doc, err := resolver.GetDocument(twinId.Did())
	assert.NilError(t, err)
	assert.Check(t, doc.DelegateControl[0].Revoked == false)

	err = advancedapi2.RevokeControlDelegationFromDocument(resolver, "#newDeleg", twinId)

	doc, err = resolver.GetDocument(twinId.Did())
	assert.NilError(t, err)
	assert.Check(t, len(doc.DelegateControl) == 1)
	assert.Check(t, doc.DelegateControl[0].Revoked == true)
}

func Test_can_revoke_auth_delegation(t *testing.T) {
	resolver := test.NewInMemoryResolver()
	twinId, err := advancedapi2.NewRegisteredIdentity(resolver, identity.Twin, test.ValidKeyPairPlop, "#ExistingId", false)
	assert.NilError(t, err)

	err = advancedapi2.AddAuthenticationDelegationToDocument(resolver, "#newDeleg", test.OtherDocIssuer.String(), test.OtherProof, twinId)
	assert.NilError(t, err)

	doc, err := resolver.GetDocument(twinId.Did())
	assert.NilError(t, err)
	assert.Check(t, len(doc.DelegateAuthentication) == 1)

	err = advancedapi2.RevokeAuthenticationDelegationFromDocument(resolver, "#newDeleg", twinId)

	doc, err = resolver.GetDocument(twinId.Did())
	assert.NilError(t, err)
	assert.Check(t, len(doc.DelegateAuthentication) == 1)
	assert.Check(t, doc.DelegateAuthentication[0].Revoked == true)
}

func Test_can_validate_document(t *testing.T) {
	resolver := test.NewInMemoryResolver()
	twinId, err := advancedapi2.NewRegisteredIdentity(resolver, identity.Twin, test.ValidKeyPairPlop, "#ExistingId", false)
	assert.NilError(t, err)

	otherId, err := advancedapi2.NewRegisteredIdentity(resolver, identity.Agent, test.ValidKeyPairPlop2, "#otherId", false)
	assert.NilError(t, err)

	otherDoc, _ := resolver.GetDocument(otherId.Did())
	_, proof, err := advancedapi2.CreateDelegationProof(twinId.Issuer(), otherDoc, test.ValidKeyPairPlop2)
	assert.NilError(t, err)

	err = advancedapi2.AddControlDelegationToDocument(resolver, "#newDelegCtrl", otherId.Issuer().String(), proof.Signature, twinId)
	assert.NilError(t, err)

	err = advancedapi2.AddAuthenticationDelegationToDocument(resolver, "#newDeleg", otherId.Issuer().String(), proof.Signature, twinId)
	assert.NilError(t, err)

	doc, err := resolver.GetDocument(twinId.Did())
	assert.NilError(t, err)
	assert.Check(t, len(doc.DelegateAuthentication) == 1)
	assert.Check(t, len(doc.DelegateControl) == 1)

	err = advancedapi2.ValidateRegisterDocument(resolver, doc)
	assert.NilError(t, err)
}

func Test_can_set_document_controller(t *testing.T) {
	resolver := test.NewInMemoryResolver()
	twinId, err := advancedapi2.NewRegisteredIdentity(resolver, identity.Twin, test.ValidKeyPairPlop, "#ExistingId", false)
	assert.NilError(t, err)

	err = advancedapi2.SetDocumentController(resolver, twinId, test.OtherDocIssuer)
	assert.NilError(t, err)

	doc, err := resolver.GetDocument(twinId.Did())
	assert.NilError(t, err)
	assert.Check(t, doc.Controller == test.OtherDocIssuer.Did)
}

func Test_can_set_document_creator(t *testing.T) {
	resolver := test.NewInMemoryResolver()
	twinId, err := advancedapi2.NewRegisteredIdentity(resolver, identity.Twin, test.ValidKeyPairPlop, "#ExistingId", false)
	assert.NilError(t, err)

	err = advancedapi2.SetDocumentCreator(resolver, twinId, test.OtherDocIssuer)
	assert.NilError(t, err)

	doc, err := resolver.GetDocument(twinId.Did())
	assert.NilError(t, err)
	assert.Check(t, doc.Creator == test.OtherDocIssuer.Did)
}

func Test_can_set_document_revoked(t *testing.T) {
	resolver := test.NewInMemoryResolver()
	twinId, err := advancedapi2.NewRegisteredIdentity(resolver, identity.Twin, test.ValidKeyPairPlop, "#ExistingId", false)
	assert.NilError(t, err)

	err = advancedapi2.SetDocumentRevoked(resolver, twinId, true)
	assert.NilError(t, err)

	doc, err := resolver.GetDocument(twinId.Did())
	assert.NilError(t, err)
	assert.Check(t, doc.Revoked == true)
}

func Test_can_remove_public_key(t *testing.T) {
	resolver := test.NewInMemoryResolver()
	twinId, err := advancedapi2.NewRegisteredIdentity(resolver, identity.Twin, test.ValidKeyPairPlop, "#ExistingId", false)
	assert.NilError(t, err)

	err = advancedapi2.AddPublicKeyToDocument(resolver, "#NewPub", test.ValidKeyPairPlop2.PublicKeyBase58, twinId)
	assert.NilError(t, err)

	err = advancedapi2.RemovePublicKeyFromDocument(resolver, "#NewPub", twinId)
	assert.NilError(t, err)

	doc, err := resolver.GetDocument(twinId.Did())
	assert.NilError(t, err)

	assert.Check(t, len(doc.PublicKeys) == 1)
}

func Test_can_revoke_public_key(t *testing.T) {
	resolver := test.NewInMemoryResolver()
	twinId, err := advancedapi2.NewRegisteredIdentity(resolver, identity.Twin, test.ValidKeyPairPlop, "#ExistingId", false)
	assert.NilError(t, err)

	err = advancedapi2.RevokePublicKeyFromDocument(resolver, twinId.Issuer().Name, twinId)
	assert.NilError(t, err)

	doc, err := resolver.GetDocument(twinId.Did())
	assert.NilError(t, err)

	assert.Check(t, len(doc.PublicKeys) == 1)
	assert.Check(t, doc.PublicKeys[0].Revoked == true)
}

func Test_can_remove_auth_key(t *testing.T) {
	resolver := test.NewInMemoryResolver()
	twinId, err := advancedapi2.NewRegisteredIdentity(resolver, identity.Twin, test.ValidKeyPairPlop, "#ExistingId", false)
	assert.NilError(t, err)

	err = advancedapi2.AddAuthenticationKeyToDocument(resolver, "#NewAuth", test.ValidKeyPairPlop2.PublicKeyBase58, twinId)
	assert.NilError(t, err)

	err = advancedapi2.RemoveAuthenticationKeyFromDocument(resolver, "#NewAuth", twinId)
	assert.NilError(t, err)

	doc, err := resolver.GetDocument(twinId.Did())
	assert.NilError(t, err)

	assert.Check(t, len(doc.AuthenticationKeys) == 0)
}

func Test_can_revoke_auth_key(t *testing.T) {
	resolver := test.NewInMemoryResolver()
	twinId, err := advancedapi2.NewRegisteredIdentity(resolver, identity.Twin, test.ValidKeyPairPlop, "#ExistingId", false)
	assert.NilError(t, err)

	err = advancedapi2.AddAuthenticationKeyToDocument(resolver, "#NewAuth", test.ValidKeyPairPlop2.PublicKeyBase58, twinId)
	assert.NilError(t, err)

	err = advancedapi2.RevokeAuthenticationKeyFromDocument(resolver, "#NewAuth", twinId)
	assert.NilError(t, err)

	doc, err := resolver.GetDocument(twinId.Did())
	assert.NilError(t, err)

	assert.Check(t, len(doc.AuthenticationKeys) == 1)
	assert.Check(t, doc.AuthenticationKeys[0].Revoked == true)
}

func Test_can_create_agent_auth_token(t *testing.T) {
	resolver := test.NewInMemoryResolver()
	agentId, err := advancedapi2.NewRegisteredIdentity(resolver, identity.Agent, test.ValidKeyPairPlop, "#agent", false)
	assert.NilError(t, err)
	userId, err := advancedapi2.NewRegisteredIdentity(resolver, identity.User, test.ValidKeyPairPlop2, "#user", false)
	assert.NilError(t, err)

	agentDoc, _ := resolver.GetDocument(agentId.Did())
	_, proof, err := advancedapi2.CreateDelegationProof(userId.Issuer(), agentDoc, agentId.KeyPair())
	assert.NilError(t, err)

	err = advancedapi2.AddAuthenticationDelegationToDocument(resolver, "#deleg", agentId.Issuer().String(), proof.Signature, userId)
	assert.NilError(t, err)

	duration, _ := time.ParseDuration("10s")
	token, err := advancedapi2.CreateAgentAuthToken(agentId, userId.Did(), duration, "audience", 0)
	assert.NilError(t, err)
	assert.Check(t, len(string(token)) > 0)
}

func Test_can_create_twin_auth_token(t *testing.T) {
	resolver := test.NewInMemoryResolver()
	twinId, err := advancedapi2.NewRegisteredIdentity(resolver, identity.Twin, test.ValidKeyPairPlop2, "#twin", false)
	assert.NilError(t, err)

	duration, _ := time.ParseDuration("10s")
	token, err := advancedapi2.CreateTwinAuthToken(twinId, duration, "audience", 01)
	assert.NilError(t, err)
	assert.Check(t, len(string(token)) > 0)
}

func Test_can_create_identifier(t *testing.T) {
	id, err := advancedapi2.CreateIdentifier(test.ValidKeyPairPlop.PublicKeyBytes)
	assert.NilError(t, err)
	assert.Check(t, id == "did:iotics:iotFqH94g4jG58XNMDK9k5YCmQgcpNPUhWFx")
}

func Test_can_validate_document_proof(t *testing.T) {
	resolver := test.NewInMemoryResolver()
	twinId, err := advancedapi2.NewRegisteredIdentity(resolver, identity.Twin, test.ValidKeyPairPlop, "#ExistingId", false)
	assert.NilError(t, err)

	doc, err := resolver.GetDocument(twinId.Did())
	assert.NilError(t, err)

	err = advancedapi2.ValidateDocumentProof(doc)
	assert.NilError(t, err)
}

func Test_cannot_validate_document_proof(t *testing.T) {
	resolver := test.NewInMemoryResolver()
	twinId, err := advancedapi2.NewRegisteredIdentity(resolver, identity.Twin, test.ValidKeyPairPlop, "#ExistingId", false)
	assert.NilError(t, err)

	_ = advancedapi2.RemovePublicKeyFromDocument(resolver, "#ExistingId", twinId)

	doc, err := resolver.GetDocument(twinId.Did())
	assert.NilError(t, err)

	err = advancedapi2.ValidateDocumentProof(doc)
	assert.ErrorContains(t, err, "unable to find public key matching document ID")
}

func Test_can_create_seed(t *testing.T) {
	seed, err := advancedapi2.CreateSeed(128)
	assert.NilError(t, err)
	assert.Check(t, len(seed) == 16)

	seed, err = advancedapi2.CreateSeed(256)
	assert.NilError(t, err)
	assert.Check(t, len(seed) == 32)

	_, err = advancedapi2.CreateSeed(384)
	assert.ErrorContains(t, err, "length must be 128 or 256")
}
