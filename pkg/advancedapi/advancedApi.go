// Copyright (c) IOTIC LABS LIMITED. All rights reserved. Licensed under the Apache License, Version 2.0.

package advancedapi

import (
	"context"
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
func RegisterUpdatedDocument(
	ctx context.Context, resolverClient register.ResolverClient, doc *register.RegisterDocument,
	keypair *crypto.KeyPair, issuer *register.Issuer,
) error {
	return resolverClient.RegisterDocument(ctx, doc, keypair.PrivateKey, issuer)
}

// GetRegisterDocument Get a register document from the resolver.
func GetRegisterDocument(
	ctx context.Context, resolverClient register.ResolverClient, did string,
) (*register.RegisterDocument, error) {
	return resolverClient.GetDocument(ctx, did)
}

// CreateNewDocumentAndRegister Create and register a new document against the resolver.
func CreateNewDocumentAndRegister(
	ctx context.Context, resolverClient register.ResolverClient, keyPair *crypto.KeyPair, purpose identity.DidType,
	name string, override bool,
) (*register.RegisterDocument, error) {
	registerDocument, issuer, err := CreateNewDocument(purpose, keyPair, name)
	if err != nil {
		return nil, err
	}

	if !override {
		getDoc, err := GetRegisterDocument(ctx, resolverClient, issuer.Did)
		if err != nil {
			rerr, ok := err.(*register.ResolverError)
			if ok && rerr.ErrorType() == register.NotFound {
				// Ignore not found error
			} else {
				return nil, err
			}
		}

		if getDoc != nil {
			return getDoc, nil
		}
	}

	err = RegisterUpdatedDocument(ctx, resolverClient, registerDocument, keyPair, issuer)
	if err != nil {
		return nil, err
	}

	return registerDocument, nil
}

// CreateNewIdentityAndRegister Create and register a new registered identity and its associated register document against the resolver.
func CreateNewIdentityAndRegister(
	ctx context.Context, resolverClient register.ResolverClient, purpose identity.DidType, keyPair *crypto.KeyPair,
	name string, override bool,
) (register.RegisteredIdentity, *register.RegisterDocument, error) {
	doc, err := CreateNewDocumentAndRegister(ctx, resolverClient, keyPair, purpose, name, override)
	if err != nil {
		return nil, nil, err
	}

	issuer, err := register.NewIssuer(doc.ID, doc.PublicKeys[0].ID)
	if err != nil {
		return nil, nil, err
	}

	regID := register.NewRegisteredIdentity(keyPair, issuer)
	return regID, doc, nil
}

// ValidateRegisterDocument Validate a register document against the resolver.
func ValidateRegisterDocument(
	ctx context.Context, resolverClient register.ResolverClient, document *register.RegisterDocument,
) error {
	// Note: This function matches the python implementation
	// Validate a register document against the resolver if one of the register document delegation proof is invalid
	// What it actually does it validate the delegations on the passed document

	for i := range document.DelegateControl {
		err := register.ValidateDelegation(ctx, resolverClient, document.ID, &document.DelegateControl[i])
		if err != nil {
			return err
		}
	}
	for i := range document.DelegateAuthentication {
		err := register.ValidateDelegation(ctx, resolverClient, document.ID, &document.DelegateAuthentication[i])
		if err != nil {
			return err
		}
	}

	return nil
}

// SetDocumentController Set register document controller issuer.
func SetDocumentController(
	ctx context.Context, resolverClient register.ResolverClient, originalDoc *register.RegisterDocument,
	identity register.RegisteredIdentity, controller *register.Issuer,
) error {
	var err error

	if originalDoc == nil {
		originalDoc, err = GetRegisterDocument(ctx, resolverClient, identity.Did())
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

	return RegisterUpdatedDocument(ctx, resolverClient, updatedDoc, identity.KeyPair(), identity.Issuer())
}

// SetDocumentCreator Set register document creator.
func SetDocumentCreator(
	ctx context.Context, resolverClient register.ResolverClient, originalDoc *register.RegisterDocument,
	identity register.RegisteredIdentity, creator *register.Issuer,
) error {
	var err error

	if originalDoc == nil {
		originalDoc, err = GetRegisterDocument(ctx, resolverClient, identity.Did())
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

	return RegisterUpdatedDocument(ctx, resolverClient, updatedDoc, identity.KeyPair(), identity.Issuer())
}

// SetDocumentRevoked Set register document revoke field.
func SetDocumentRevoked(
	ctx context.Context, resolverClient register.ResolverClient, originalDoc *register.RegisterDocument,
	identity register.RegisteredIdentity, revoked bool,
) error {
	var err error

	if originalDoc == nil {
		originalDoc, err = GetRegisterDocument(ctx, resolverClient, identity.Did())
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

	return RegisterUpdatedDocument(ctx, resolverClient, updatedDoc, identity.KeyPair(), identity.Issuer())
}

// AddPublicKeyToDocument Add a new register public key to a register document.
func AddPublicKeyToDocument(
	ctx context.Context, resolverClient register.ResolverClient, originalDoc *register.RegisterDocument, name string,
	publicBase58 string, identity register.RegisteredIdentity,
) error {
	var err error

	if originalDoc == nil {
		originalDoc, err = GetRegisterDocument(ctx, resolverClient, identity.Did())
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

	return RegisterUpdatedDocument(ctx, resolverClient, updatedDoc, identity.KeyPair(), identity.Issuer())
}

func removeKeyFromDocument(
	ctx context.Context, resolverClient register.ResolverClient, originalDoc *register.RegisterDocument, name string,
	identity register.RegisteredIdentity,
) error {
	var err error

	if originalDoc == nil {
		originalDoc, err = GetRegisterDocument(ctx, resolverClient, identity.Did())
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

	return RegisterUpdatedDocument(ctx, resolverClient, updatedDoc, identity.KeyPair(), identity.Issuer())
}

func revokeKeyFromDocument(
	ctx context.Context, resolverClient register.ResolverClient, originalDoc *register.RegisterDocument, name string,
	identity register.RegisteredIdentity,
) error {
	var err error

	if originalDoc == nil {
		originalDoc, err = GetRegisterDocument(ctx, resolverClient, identity.Did())
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

	return RegisterUpdatedDocument(ctx, resolverClient, updatedDoc, identity.KeyPair(), identity.Issuer())
}

// RemovePublicKeyFromDocument Remove a register public key from a register document.
func RemovePublicKeyFromDocument(
	ctx context.Context, resolverClient register.ResolverClient, originalDoc *register.RegisterDocument, name string,
	identity register.RegisteredIdentity,
) error {
	return removeKeyFromDocument(ctx, resolverClient, originalDoc, name, identity)
}

// RevokePublicKeyFromDocument Set register public key revoke field.
func RevokePublicKeyFromDocument(
	ctx context.Context, resolverClient register.ResolverClient, originalDoc *register.RegisterDocument, name string,
	identity register.RegisteredIdentity,
) error {
	return revokeKeyFromDocument(ctx, resolverClient, originalDoc, name, identity)
}

// AddAuthenticationKeyToDocument Add a new register authentication public key to a register document.
func AddAuthenticationKeyToDocument(
	ctx context.Context, resolverClient register.ResolverClient, originalDoc *register.RegisterDocument, name string,
	publicBase58 string, identity register.RegisteredIdentity,
) error {
	var err error

	if originalDoc == nil {
		originalDoc, err = GetRegisterDocument(ctx, resolverClient, identity.Did())
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

	return RegisterUpdatedDocument(ctx, resolverClient, updatedDoc, identity.KeyPair(), identity.Issuer())
}

// RemoveAuthenticationKeyFromDocument Remove a register authentication public key from a register document.
func RemoveAuthenticationKeyFromDocument(
	ctx context.Context, resolverClient register.ResolverClient, originalDoc *register.RegisterDocument, name string,
	identity register.RegisteredIdentity,
) error {
	return removeKeyFromDocument(ctx, resolverClient, originalDoc, name, identity)
}

// RevokeAuthenticationKeyFromDocument Set register authentication public key revoke field.
func RevokeAuthenticationKeyFromDocument(
	ctx context.Context, resolverClient register.ResolverClient, originalDoc *register.RegisterDocument, name string,
	identity register.RegisteredIdentity,
) error {
	return revokeKeyFromDocument(ctx, resolverClient, originalDoc, name, identity)
}

// AddAuthenticationDelegationToDocument Add register authentication did delegation proof to a register document.
func AddAuthenticationDelegationToDocument(
	ctx context.Context, resolverClient register.ResolverClient, originalDoc *register.RegisterDocument, name string,
	controller string, proof string, identity register.RegisteredIdentity,
) error {
	return addDelegationToDocument(ctx, resolverClient, originalDoc, identity,
		register.AddAuthenticationDelegation(name, controller, proof, register.DidProof, false))
}

// AddGenericAuthenticationDelegationToDocument Add register authentication generic delegation proof to a register document.
func AddGenericAuthenticationDelegationToDocument(
	ctx context.Context, resolverClient register.ResolverClient, originalDoc *register.RegisterDocument, name string,
	controller string, proof string, identity register.RegisteredIdentity,
) error {
	return addDelegationToDocument(ctx, resolverClient, originalDoc, identity,
		register.AddAuthenticationDelegation(name, controller, proof, register.GenericProof, false))
}

// RemoveAuthenticationDelegationFromDocument Remove register authentication delegation proof from a register document.
func RemoveAuthenticationDelegationFromDocument(
	ctx context.Context, resolverClient register.ResolverClient, originalDoc *register.RegisterDocument, name string,
	identity register.RegisteredIdentity,
) error {
	return removeKeyFromDocument(ctx, resolverClient, originalDoc, name, identity)
}

// RevokeAuthenticationDelegationFromDocument Set register authentication delegation proof revoke field.
func RevokeAuthenticationDelegationFromDocument(
	ctx context.Context, resolverClient register.ResolverClient, originalDoc *register.RegisterDocument, name string,
	identity register.RegisteredIdentity,
) error {
	return revokeKeyFromDocument(ctx, resolverClient, originalDoc, name, identity)
}

func addDelegationToDocument(
	ctx context.Context, resolverClient register.ResolverClient, originalDoc *register.RegisterDocument,
	identity register.RegisteredIdentity, addDelegationOpts register.RegisterDocumentOpts,
) error {
	var err error

	if originalDoc == nil {
		originalDoc, err = GetRegisterDocument(ctx, resolverClient, identity.Did())
		if err != nil {
			return err
		}
	}

	opts := []register.RegisterDocumentOpts{
		register.AddFromExistingDocument(originalDoc),
		addDelegationOpts,
	}
	updatedDoc, errs := register.NewRegisterDocument(opts)
	if len(errs) != 0 {
		return fmt.Errorf("error while creating new RegisterDocument: %v", errs)
	}

	return RegisterUpdatedDocument(ctx, resolverClient, updatedDoc, identity.KeyPair(), identity.Issuer())
}

// AddControlDelegationToDocument Add register control did delegation proof to a register document.
func AddControlDelegationToDocument(
	ctx context.Context, resolverClient register.ResolverClient, originalDoc *register.RegisterDocument, name string,
	controller string, proof string, identity register.RegisteredIdentity,
) error {
	return addDelegationToDocument(ctx, resolverClient, originalDoc, identity,
		register.AddControlDelegation(name, controller, proof, register.DidProof, false))
}

// AddGenericControlDelegationToDocument Add register control generic delegation proof to a register document.
func AddGenericControlDelegationToDocument(
	ctx context.Context, resolverClient register.ResolverClient, originalDoc *register.RegisterDocument, name string,
	controller string, proof string, identity register.RegisteredIdentity,
) error {
	return addDelegationToDocument(ctx, resolverClient, originalDoc, identity,
		register.AddControlDelegation(name, controller, proof, register.GenericProof, false))
}

// RemoveControlDelegationFromDocument Remove register control delegation proof from a register document.
func RemoveControlDelegationFromDocument(
	ctx context.Context, resolverClient register.ResolverClient, originalDoc *register.RegisterDocument, name string,
	identity register.RegisteredIdentity,
) error {
	return removeKeyFromDocument(ctx, resolverClient, originalDoc, name, identity)
}

// RevokeControlDelegationFromDocument Set register control delegation proof revoke field.
func RevokeControlDelegationFromDocument(
	ctx context.Context, resolverClient register.ResolverClient, originalDoc *register.RegisterDocument, name string,
	identity register.RegisteredIdentity,
) error {
	return revokeKeyFromDocument(ctx, resolverClient, originalDoc, name, identity)
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
	ProofType          *register.DelegationProofType
}

func (opts DelegationOpts) getProofType() register.DelegationProofType {
	if opts.ProofType == nil {
		return register.DidProof
	}
	return *opts.ProofType
}

func delegate(ctx context.Context, opts DelegationOpts, IsControl bool) error {
	var err error

	delegatingDoc := opts.DelegatingDocument
	if delegatingDoc == nil {
		delegatingDoc, err = GetRegisterDocument(ctx, opts.ResolverClient, opts.DelegatingDid)
		if err != nil {
			return err
		}
	}

	subjectDoc := opts.SubjectDocument
	if subjectDoc == nil {
		subjectDoc, err = GetRegisterDocument(ctx, opts.ResolverClient, opts.SubjectDid)
		if err != nil {
			return err
		}
	}

	delegatingIssuer, err := GetIssuerByPublicKey(delegatingDoc, opts.DelegatingKeyPair.PublicKeyBase58)
	if err != nil {
		return err
	}
	var subjectIssuer *register.Issuer
	var dProof *proof.Proof
	var proofType = opts.getProofType()
	if proofType == register.GenericProof {
		subjectIssuer, dProof, err = CreateGenericDelegationProof(subjectDoc, opts.SubjectKeyPair)
		if err != nil {
			return err
		}
	} else {
		subjectIssuer, dProof, err = CreateDelegationProof(delegatingIssuer, subjectDoc, opts.SubjectKeyPair)
		if err != nil {
			return err
		}
	}

	delegFunc := register.AddAuthenticationDelegation
	if IsControl {
		delegFunc = register.AddControlDelegation
	}

	regOpts := []register.RegisterDocumentOpts{
		register.AddFromExistingDocument(delegatingDoc),
		delegFunc(opts.Name, subjectIssuer.String(), dProof.Signature, proofType, false),
	}
	updatedDoc, errs := register.NewRegisterDocument(regOpts)
	if len(errs) != 0 {
		return fmt.Errorf("error while creating new RegisterDocument: %v", errs)
	}

	return RegisterUpdatedDocument(ctx, opts.ResolverClient, updatedDoc, opts.DelegatingKeyPair, delegatingIssuer)
}

// DelegateAuthentication Delegate authentication between delegating registered identity and delegated registered identity.
func DelegateAuthentication(ctx context.Context, opts DelegationOpts) error {
	return delegate(ctx, opts, false)
}

// DelegateControl Delegate control between delegating registered identity and delegated registered identity.
// - delegating is user or twin
// - subject is always agent
func DelegateControl(ctx context.Context, opts DelegationOpts) error {
	return delegate(ctx, opts, true)
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
func CreateAgentAuthToken(
	agentID register.RegisteredIdentity, userDid string, duration time.Duration, audience string, startOffset int,
) (register.JwtToken, error) {
	return register.CreateAuthToken(agentID.Issuer(), userDid, audience, duration, agentID.KeyPair().PrivateKey, startOffset)
}

// CreateTwinAuthToken Create a twin authentication token.
func CreateTwinAuthToken(
	twinIdentity register.RegisteredIdentity, duration time.Duration, audience string, startOffset int,
) (register.JwtToken, error) {
	return register.CreateAuthToken(twinIdentity.Issuer(), twinIdentity.Issuer().Did, audience, duration, twinIdentity.KeyPair().PrivateKey, startOffset)
}

// CreateProof Create a proof.
func CreateProof(keyPair *crypto.KeyPair, issuer *register.Issuer, content []byte) (*proof.Proof, error) {
	return proof.NewProof(keyPair.PrivateKey, issuer.Did, issuer.Name, content)
}

func createProof(
	subjectDoc *register.RegisterDocument, subjectKeyPair *crypto.KeyPair, content []byte,
) (*register.Issuer, *proof.Proof, error) {
	for _, v := range subjectDoc.PublicKeys {
		if v.PublicKeyBase58 == subjectKeyPair.PublicKeyBase58 {
			issuer, err := register.NewIssuer(subjectDoc.ID, v.ID)
			if err != nil {
				return nil, nil, err
			}

			dProof, err := CreateProof(subjectKeyPair, issuer, content)
			if err != nil {
				return nil, nil, err
			}
			return issuer, dProof, nil
		}
	}
	return nil, nil, fmt.Errorf("unable to find public key in document matching key pair secrets")
}

// CreateDelegationProof Create a proof that can be used to setup a delegation from a single delegating issuer doc.
// The signed proof content is the encoded DID Identifier of the delegating issuer doc.
func CreateDelegationProof(
	delegatingIssuer *register.Issuer, subjectDoc *register.RegisterDocument, subjectKeyPair *crypto.KeyPair,
) (*register.Issuer, *proof.Proof, error) {
	return createProof(subjectDoc, subjectKeyPair, []byte(delegatingIssuer.Did))
}

// CreateGenericDelegationProof Create a proof that can be used to setup a delegation from several delegating issuers doc.
// The signed proof content is an empty byte array.
func CreateGenericDelegationProof(
	subjectDoc *register.RegisterDocument, subjectKeyPair *crypto.KeyPair,
) (*register.Issuer, *proof.Proof, error) {
	return createProof(subjectDoc, subjectKeyPair, []byte(""))
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

// NewNameOrDefault Produce default name or validate passed name
func NewNameOrDefault(purpose identity.DidType, name string) (string, error) {
	if name == "" {
		name = identity.MakeName(purpose)
	}
	err := validation.ValidateKeyName(name)
	if err != nil {
		return "", err
	}

	return name, nil
}

// NewIssuerByKeypair Create a new registered identity and its associated register document using KeyPair.
func NewIssuerByKeypair(purpose identity.DidType, keyPair *crypto.KeyPair, name string) (*register.Issuer, error) {
	did, err := identity.MakeIdentifier(keyPair.PublicKeyBytes)
	if err != nil {
		return nil, err
	}

	name, err = NewNameOrDefault(purpose, name)
	if err != nil {
		return nil, err
	}

	issuer, err := register.NewIssuer(did, name)
	if err != nil {
		return nil, err
	}

	return issuer, nil
}

// CreateNewDocument return a new RegisterDocument and Issuer, the local offline part of CreateNewDocumentAndRegister.
func CreateNewDocument(
	purpose identity.DidType, keyPair *crypto.KeyPair, name string,
) (*register.RegisterDocument, *register.Issuer, error) {
	issuer, err := NewIssuerByKeypair(purpose, keyPair, name)
	if err != nil {
		return nil, nil, err
	}

	docProof, err := CreateProof(keyPair, issuer, []byte(issuer.Did))
	if err != nil {
		return nil, nil, err
	}

	opts := []register.RegisterDocumentOpts{
		register.AddRootParams(issuer.Did, purpose, docProof.Signature, false),
		register.AddPublicKey(issuer.Name, keyPair.PublicKeyBase58, false),
	}
	registerDocument, errs := register.NewRegisterDocument(opts)
	if len(errs) != 0 {
		return nil, nil, fmt.Errorf("error while creating new RegisterDocument: %v", errs)
	}

	return registerDocument, issuer, nil
}
