// Copyright (c) IOTIC LABS LIMITED. All rights reserved. Licensed under the Apache License, Version 2.0.

package advancedapi

import (
	"fmt"
	"time"

	"github.com/Iotic-Labs/iotics-identity-go/pkg/crypto"
	"github.com/Iotic-Labs/iotics-identity-go/pkg/identity"
	"github.com/Iotic-Labs/iotics-identity-go/pkg/proof"
	"github.com/Iotic-Labs/iotics-identity-go/pkg/register"
	"github.com/Iotic-Labs/iotics-identity-go/pkg/validation"
	"github.com/jbenet/go-base58"
)

// RegisterUpdatedDocument Register a new version of a register document against the resolver.
func RegisterUpdatedDocument(resolverClient register.ResolverClient, doc *register.RegisterDocument, keypair *crypto.KeyPair, issuer *register.Issuer) error {
	return resolverClient.RegisterDocument(doc, keypair.PrivateKey, issuer)
}

// GetRegisterDocument Get a register document from the resolver.
func GetRegisterDocument(resolverClient register.ResolverClient, did string) (*register.RegisterDocument, error) {
	return resolverClient.GetDocument(did)
}

// RegisterNewDocument Create and register a new document against the resolver.
func RegisterNewDocument(resolverClient register.ResolverClient, keyPair *crypto.KeyPair, purpose identity.DidType, name string, override bool) (*register.RegisterDocument, error) {
	did, err := identity.MakeIdentifier(keyPair.PublicKeyBytes)
	if err != nil {
		return nil, err
	}

	if !override {
		getDoc, _ := GetRegisterDocument(resolverClient, did)
		if getDoc != nil {
			return getDoc, nil
		}
	}

	issuer, err := register.NewIssuer(did, name)
	if err != nil {
		return nil, err
	}
	docProof, err := CreateProof(keyPair, issuer, []byte(issuer.Did))
	if err != nil {
		return nil, err
	}

	opts := []register.RegisterDocumentOpts{
		register.AddRootParams(did, purpose, docProof.Signature, false),
		register.AddPublicKey(name, keyPair.PublicKeyBase58, false),
	}
	registerDocument, errs := register.NewRegisterDocument(opts)
	if len(errs) != 0 {
		return nil, fmt.Errorf("error while creating new RegisterDocument: %v", errs)
	}

	err = RegisterUpdatedDocument(resolverClient, registerDocument, keyPair, issuer)
	if err != nil {
		return nil, err
	}

	return registerDocument, nil
}

// RegisterNewIdentity Create and register a new registered identity and its associated register document against the resolver.
func RegisterNewIdentity(resolverClient register.ResolverClient, purpose identity.DidType, keyPair *crypto.KeyPair, name string, override bool) (register.RegisteredIdentity, *register.RegisterDocument, error) {
	did, err := identity.MakeIdentifier(keyPair.PublicKeyBytes)
	if err != nil {
		return nil, nil, err
	}

	if name == "" {
		name = identity.MakeName(purpose)
	}
	err = validation.ValidateKeyName(name)
	if err != nil {
		return nil, nil, err
	}

	issuer, err := register.NewIssuer(did, name)
	if err != nil {
		return nil, nil, err
	}

	doc, err := RegisterNewDocument(resolverClient, keyPair, purpose, name, override)
	if err != nil {
		return nil, nil, err
	}

	regID := register.NewRegisteredIdentity(keyPair, issuer)
	return regID, doc, nil
}

// ValidateRegisterDocument Validate a register document against the resolver.
func ValidateRegisterDocument(resolverClient register.ResolverClient, document *register.RegisterDocument) error {
	// Note: This function matches the python implementation
	// Validate a register document against the resolver if one of the register document delegation proof is invalid
	// What it actually does it validate the delegations on the passed document

	for _, v := range document.DelegateControl {
		err := register.ValidateDelegation(resolverClient, document.ID, &v)
		if err != nil {
			return err
		}
	}
	for _, v := range document.DelegateAuthentication {
		err := register.ValidateDelegation(resolverClient, document.ID, &v)
		if err != nil {
			return err
		}
	}

	return nil
}

// SetDocumentController Set register document controller issuer.
func SetDocumentController(resolverClient register.ResolverClient, originalDoc *register.RegisterDocument, identity register.RegisteredIdentity, controller *register.Issuer) error {
	var err error

	if originalDoc == nil {
		originalDoc, err = GetRegisterDocument(resolverClient, identity.Did())
		if err != nil {
			return err
		}
	}

	opts := []register.RegisterDocumentOpts{
		register.AddFromExistingDocument(originalDoc),
		register.SetDocumentController(controller.Did),
	}
	updatedDoc, errs := register.NewRegisterDocument(opts)
	if len(errs) != 0 {
		return fmt.Errorf("error while creating new RegisterDocument: %v", errs)
	}

	return RegisterUpdatedDocument(resolverClient, updatedDoc, identity.KeyPair(), identity.Issuer())
}

// SetDocumentCreator Set register document creator.
func SetDocumentCreator(resolverClient register.ResolverClient, originalDoc *register.RegisterDocument, identity register.RegisteredIdentity, creator *register.Issuer) error {
	var err error

	if originalDoc == nil {
		originalDoc, err = GetRegisterDocument(resolverClient, identity.Did())
		if err != nil {
			return err
		}
	}

	opts := []register.RegisterDocumentOpts{
		register.AddFromExistingDocument(originalDoc),
		register.SetDocumentCreator(creator.Did),
	}
	updatedDoc, errs := register.NewRegisterDocument(opts)
	if len(errs) != 0 {
		return fmt.Errorf("error while creating new RegisterDocument: %v", errs)
	}

	return RegisterUpdatedDocument(resolverClient, updatedDoc, identity.KeyPair(), identity.Issuer())
}

// SetDocumentRevoked Set register document revoke field.
func SetDocumentRevoked(resolverClient register.ResolverClient, originalDoc *register.RegisterDocument, identity register.RegisteredIdentity, revoked bool) error {
	var err error

	if originalDoc == nil {
		originalDoc, err = GetRegisterDocument(resolverClient, identity.Did())
		if err != nil {
			return err
		}
	}

	opts := []register.RegisterDocumentOpts{
		register.AddFromExistingDocument(originalDoc),
		register.SetDocumentRevoked(revoked),
	}
	updatedDoc, errs := register.NewRegisterDocument(opts)
	if len(errs) != 0 {
		return fmt.Errorf("error while creating new RegisterDocument: %v", errs)
	}

	return RegisterUpdatedDocument(resolverClient, updatedDoc, identity.KeyPair(), identity.Issuer())
}

// AddPublicKeyToDocument Add a new register public key to a register document.
func AddPublicKeyToDocument(resolverClient register.ResolverClient, originalDoc *register.RegisterDocument, name string, publicBase58 string, identity register.RegisteredIdentity) error {
	var err error

	if originalDoc == nil {
		originalDoc, err = GetRegisterDocument(resolverClient, identity.Did())
		if err != nil {
			return err
		}
	}

	opts := []register.RegisterDocumentOpts{
		register.AddFromExistingDocument(originalDoc),
		register.AddPublicKey(name, publicBase58, false),
	}
	updatedDoc, errs := register.NewRegisterDocument(opts)
	if len(errs) != 0 {
		return fmt.Errorf("error while creating new RegisterDocument: %v", errs)
	}

	return RegisterUpdatedDocument(resolverClient, updatedDoc, identity.KeyPair(), identity.Issuer())
}

func removeKeyFromDocument(resolverClient register.ResolverClient, originalDoc *register.RegisterDocument, name string, identity register.RegisteredIdentity) error {
	var err error

	if originalDoc == nil {
		originalDoc, err = GetRegisterDocument(resolverClient, identity.Did())
		if err != nil {
			return err
		}
	}

	opts := []register.RegisterDocumentOpts{
		register.AddFromExistingDocument(originalDoc),
		register.RemoveKey(name),
	}
	updatedDoc, errs := register.NewRegisterDocument(opts)
	if len(errs) != 0 {
		return fmt.Errorf("error while creating new RegisterDocument: %v", errs)
	}

	return RegisterUpdatedDocument(resolverClient, updatedDoc, identity.KeyPair(), identity.Issuer())
}

func revokeKeyFromDocument(resolverClient register.ResolverClient, originalDoc *register.RegisterDocument, name string, identity register.RegisteredIdentity) error {
	var err error

	if originalDoc == nil {
		originalDoc, err = GetRegisterDocument(resolverClient, identity.Did())
		if err != nil {
			return err
		}
	}

	opts := []register.RegisterDocumentOpts{
		register.AddFromExistingDocument(originalDoc),
		register.RevokeKey(name),
	}
	updatedDoc, errs := register.NewRegisterDocument(opts)
	if len(errs) != 0 {
		return fmt.Errorf("error while creating new RegisterDocument: %v", errs)
	}

	return RegisterUpdatedDocument(resolverClient, updatedDoc, identity.KeyPair(), identity.Issuer())
}

// RemovePublicKeyFromDocument Remove a register public key from a register document.
func RemovePublicKeyFromDocument(resolverClient register.ResolverClient, originalDoc *register.RegisterDocument, name string, identity register.RegisteredIdentity) error {
	return removeKeyFromDocument(resolverClient, originalDoc, name, identity)
}

// RevokePublicKeyFromDocument Set register public key revoke field.
func RevokePublicKeyFromDocument(resolverClient register.ResolverClient, originalDoc *register.RegisterDocument, name string, identity register.RegisteredIdentity) error {
	return revokeKeyFromDocument(resolverClient, originalDoc, name, identity)
}

// AddAuthenticationKeyToDocument Add a new register authentication public key to a register document.
func AddAuthenticationKeyToDocument(resolverClient register.ResolverClient, originalDoc *register.RegisterDocument, name string, publicBase58 string, identity register.RegisteredIdentity) error {
	var err error

	if originalDoc == nil {
		originalDoc, err = GetRegisterDocument(resolverClient, identity.Did())
		if err != nil {
			return err
		}
	}

	opts := []register.RegisterDocumentOpts{
		register.AddFromExistingDocument(originalDoc),
		register.AddAuthenticationKey(name, publicBase58, false),
	}
	updatedDoc, errs := register.NewRegisterDocument(opts)
	if len(errs) != 0 {
		return fmt.Errorf("error while creating new RegisterDocument: %v", errs)
	}

	return RegisterUpdatedDocument(resolverClient, updatedDoc, identity.KeyPair(), identity.Issuer())
}

// RemoveAuthenticationKeyFromDocument Remove a register authentication public key from a register document.
func RemoveAuthenticationKeyFromDocument(resolverClient register.ResolverClient, originalDoc *register.RegisterDocument, name string, identity register.RegisteredIdentity) error {
	return removeKeyFromDocument(resolverClient, originalDoc, name, identity)
}

// RevokeAuthenticationKeyFromDocument Set register authentication public key revoke field.
func RevokeAuthenticationKeyFromDocument(resolverClient register.ResolverClient, originalDoc *register.RegisterDocument, name string, identity register.RegisteredIdentity) error {
	return revokeKeyFromDocument(resolverClient, originalDoc, name, identity)
}

// AddAuthenticationDelegationToDocument Add register authentication delegation proof to a register document.
func AddAuthenticationDelegationToDocument(resolverClient register.ResolverClient, originalDoc *register.RegisterDocument, name string, controller string, proof string, identity register.RegisteredIdentity) error {
	var err error

	if originalDoc == nil {
		originalDoc, err = GetRegisterDocument(resolverClient, identity.Did())
		if err != nil {
			return err
		}
	}

	opts := []register.RegisterDocumentOpts{
		register.AddFromExistingDocument(originalDoc),
		register.AddAuthenticationDelegation(name, controller, proof, false),
	}
	updatedDoc, errs := register.NewRegisterDocument(opts)
	if len(errs) != 0 {
		return fmt.Errorf("error while creating new RegisterDocument: %v", errs)
	}

	return RegisterUpdatedDocument(resolverClient, updatedDoc, identity.KeyPair(), identity.Issuer())
}

// RemoveAuthenticationDelegationFromDocument Remove register authentication delegation proof from a register document.
func RemoveAuthenticationDelegationFromDocument(resolverClient register.ResolverClient, originalDoc *register.RegisterDocument, name string, identity register.RegisteredIdentity) error {
	return removeKeyFromDocument(resolverClient, originalDoc, name, identity)
}

// RevokeAuthenticationDelegationFromDocument Set register authentication delegation proof revoke field.
func RevokeAuthenticationDelegationFromDocument(resolverClient register.ResolverClient, originalDoc *register.RegisterDocument, name string, identity register.RegisteredIdentity) error {
	return revokeKeyFromDocument(resolverClient, originalDoc, name, identity)
}

// AddControlDelegationToDocument Add register control delegation proof to a register document.
func AddControlDelegationToDocument(resolverClient register.ResolverClient, originalDoc *register.RegisterDocument, name string, controller string, proof string, identity register.RegisteredIdentity) error {
	var err error

	if originalDoc == nil {
		originalDoc, err = GetRegisterDocument(resolverClient, identity.Did())
		if err != nil {
			return err
		}
	}

	opts := []register.RegisterDocumentOpts{
		register.AddFromExistingDocument(originalDoc),
		register.AddControlDelegation(name, controller, proof, false),
	}
	updatedDoc, errs := register.NewRegisterDocument(opts)
	if len(errs) != 0 {
		return fmt.Errorf("error while creating new RegisterDocument: %v", errs)
	}

	return RegisterUpdatedDocument(resolverClient, updatedDoc, identity.KeyPair(), identity.Issuer())
}

// RemoveControlDelegationFromDocument Remove register control delegation proof from a register document.
func RemoveControlDelegationFromDocument(resolverClient register.ResolverClient, originalDoc *register.RegisterDocument, name string, identity register.RegisteredIdentity) error {
	return removeKeyFromDocument(resolverClient, originalDoc, name, identity)
}

// RevokeControlDelegationFromDocument Set register control delegation proof revoke field.
func RevokeControlDelegationFromDocument(resolverClient register.ResolverClient, originalDoc *register.RegisterDocument, name string, identity register.RegisteredIdentity) error {
	return revokeKeyFromDocument(resolverClient, originalDoc, name, identity)
}

// DelegationOpts Options for delegation
type DelegationOpts struct {
	ResolverClient     register.ResolverClient
	DelegatingKeyPair  *crypto.KeyPair
	DelegatingDid      string
	DelegatingDocument *register.RegisterDocument
	SubjectKeyPair     *crypto.KeyPair
	SubjectDid         string
	SubjectDocument    *register.RegisterDocument
	Name               string
}

func delegate(opts DelegationOpts, IsControl bool) error {
	var err error

	delegatingDoc := opts.DelegatingDocument
	if delegatingDoc == nil {
		delegatingDoc, err = GetRegisterDocument(opts.ResolverClient, opts.DelegatingDid)
		if err != nil {
			return err
		}
	}

	subjectDoc := opts.SubjectDocument
	if subjectDoc == nil {
		subjectDoc, err = GetRegisterDocument(opts.ResolverClient, opts.SubjectDid)
		if err != nil {
			return err
		}
	}

	delegatingIssuer, err := GetIssuerByPublicKey(delegatingDoc, opts.DelegatingKeyPair.PublicKeyBase58)
	if err != nil {
		return err
	}

	subjectIssuer, dProof, err := CreateDelegationProof(delegatingIssuer, subjectDoc, opts.SubjectKeyPair)
	if err != nil {
		return err
	}

	delegFunc := register.AddAuthenticationDelegation
	if IsControl {
		delegFunc = register.AddControlDelegation
	}

	regOpts := []register.RegisterDocumentOpts{
		register.AddFromExistingDocument(delegatingDoc),
		delegFunc(opts.Name, subjectIssuer.String(), dProof.Signature, false),
	}
	updatedDoc, errs := register.NewRegisterDocument(regOpts)
	if len(errs) != 0 {
		return fmt.Errorf("error while creating new RegisterDocument: %v", errs)
	}

	return RegisterUpdatedDocument(opts.ResolverClient, updatedDoc, opts.DelegatingKeyPair, delegatingIssuer)
}

// DelegateAuthentication Delegate authentication between delegating registered identity and delegated registered identity.
func DelegateAuthentication(opts DelegationOpts) error {
	return delegate(opts, false)
}

// DelegateControl Delegate control between delegating registered identity and delegated registered identity.
// - delegating is user or twin
// - subject is always agent
func DelegateControl(opts DelegationOpts) error {
	return delegate(opts, true)
}

// ////////////////////// // Local functions

// GetKeyPairFromPrivateExponentHex Get keypair given the private exponent as a hex string.
func GetKeyPairFromPrivateExponentHex(privateHex string) (*crypto.KeyPair, error) {
	privateKey, err := crypto.GetPrivateKeyFromExponent(privateHex)
	if err != nil {
		return nil, err
	}
	publicBytes, publicBase58, err := crypto.GetPublicKeysFromPrivateKey(privateKey)
	if err != nil {
		return nil, err
	}
	result := &crypto.KeyPair{
		PrivateKey:      privateKey,
		PublicKeyBytes:  publicBytes,
		PublicKeyBase58: publicBase58,
	}
	return result, nil
}

// GetIssuerByPublicKey Get issuer matching the public key from a register document public keys.
func GetIssuerByPublicKey(document *register.RegisterDocument, publicBase58 string) (*register.Issuer, error) {
	for _, v := range document.PublicKeys {
		if v.PublicKeyBase58 == publicBase58 {
			issuer, err := register.NewIssuer(document.ID, v.ID)
			if err != nil {
				return nil, err
			}
			return issuer, nil
		}
	}
	return nil, fmt.Errorf("issuer not found")
}

// CreateAgentAuthToken Create an agent authentication token.
func CreateAgentAuthToken(agentID register.RegisteredIdentity, userDid string, duration time.Duration, audience string, startOffset int) (register.JwtToken, error) {
	return register.CreateAuthToken(agentID.Issuer(), userDid, audience, duration, agentID.KeyPair().PrivateKey, startOffset)
}

// CreateTwinAuthToken Create a twin authentication token.
func CreateTwinAuthToken(twinIdentity register.RegisteredIdentity, duration time.Duration, audience string, startOffset int) (register.JwtToken, error) {
	return register.CreateAuthToken(twinIdentity.Issuer(), twinIdentity.Issuer().Did, audience, duration, twinIdentity.KeyPair().PrivateKey, startOffset)
}

// CreateProof Create a proof.
func CreateProof(keyPair *crypto.KeyPair, issuer *register.Issuer, content []byte) (*proof.Proof, error) {
	return proof.NewProof(keyPair.PrivateKey, issuer.Did, issuer.Name, content)
}

// CreateDelegationProof Create a delegation proof.
func CreateDelegationProof(delegatingIssuer *register.Issuer, subjectDoc *register.RegisterDocument, subjectKeyPair *crypto.KeyPair) (*register.Issuer, *proof.Proof, error) {
	for _, v := range subjectDoc.PublicKeys {
		if v.PublicKeyBase58 == subjectKeyPair.PublicKeyBase58 {
			issuer, err := register.NewIssuer(subjectDoc.ID, v.ID)
			if err != nil {
				return nil, nil, err
			}

			dProof, err := CreateProof(subjectKeyPair, issuer, []byte(delegatingIssuer.Did))
			if err != nil {
				return nil, nil, err
			}
			return issuer, dProof, nil
		}
	}
	return nil, nil, fmt.Errorf("unable to find public key in document matching key pair secrets")
}

// CreateIdentifier Create a new decentralised identifier.
func CreateIdentifier(publicBytes []byte) (string, error) {
	return identity.MakeIdentifier(publicBytes)
}

// ValidateDocumentProof Validate a register document proof.
func ValidateDocumentProof(document *register.RegisterDocument) error {
	for _, v := range document.PublicKeys {
		publicKeyBytes := base58.DecodeAlphabet(v.PublicKeyBase58, base58.BTCAlphabet)
		did, _ := identity.MakeIdentifier(publicKeyBytes)
		if did == document.ID {
			docProof := &proof.Proof{
				IssuerDid:  document.ID,
				IssuerName: v.ID,
				Content:    []byte(document.ID),
				Signature:  document.Proof,
			}
			return proof.ValidateProof(docProof, v.PublicKeyBase58)
		}
	}
	return fmt.Errorf("unable to find public key matching document ID")
}

// CreateSeed Create a new seed (secrets).
func CreateSeed(length int) ([]byte, error) {
	return crypto.CreateSeed(length)
}

// NewIssuerByKeypair Create a new registered identity and its associated register document against the resolver.
func NewIssuerByKeypair(purpose identity.DidType, keyPair *crypto.KeyPair, name string) (*register.Issuer, error) {
	did, err := identity.MakeIdentifier(keyPair.PublicKeyBytes)
	if err != nil {
		return nil, err
	}

	if name == "" {
		name = identity.MakeName(purpose)
	}
	err = validation.ValidateKeyName(name)
	if err != nil {
		return nil, err
	}

	issuer, err := register.NewIssuer(did, name)
	if err != nil {
		return nil, err
	}

	return issuer, nil
}
