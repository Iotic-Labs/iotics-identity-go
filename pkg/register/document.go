// Copyright (c) IOTIC LABS LIMITED. All rights reserved. Licensed under the Apache License, Version 2.0.

package register

import (
	"errors"
	"fmt"

	"github.com/Iotic-Labs/iotics-identity-go/pkg/identity"
	"github.com/Iotic-Labs/iotics-identity-go/pkg/validation"
	"github.com/jbenet/go-base58"
)

const (
	// DocumentContext context in document.
	DocumentContext = "https://w3id.org/did/v1"

	// PublicKeyTypeString key type string for public key section.
	PublicKeyTypeString = "Secp256k1VerificationKey2018"

	// AuthenticationKeyTypeString key type string for authentication section.
	AuthenticationKeyTypeString = "Secp256k1SignatureAuthentication2018"

	// Metadata validation.
	maxLabelLength   int = 64
	maxCommentLength int = 512
	maxURLLength     int = 512
)

// Metadata optional structure on DID Document.
type Metadata struct {
	Label   string `json:"label,omitempty"`
	Comment string `json:"comment,omitempty"`
	URL     string `json:"url,omitempty"`
}

// RegisterPublicKey structure for key used in authentication and publicKey in lists.
type RegisterPublicKey struct {
	ID              string `json:"id"`
	Type            string `json:"type"`
	PublicKeyBase58 string `json:"publicKeyBase58"`
	Revoked         bool   `json:"revoked,omitempty"`
}

// RegisterDelegationProof structure on delegation.
type RegisterDelegationProof struct {
	ID         string              `json:"id"`
	Controller string              `json:"controller"`
	Proof      string              `json:"proof"`
	ProofType  DelegationProofType `json:"proofType,omitempty"`
	Revoked    bool                `json:"revoked,omitempty"`
}

// RegisterDocument structure for document data.
type RegisterDocument struct {
	Context                string                    `json:"@context"`
	ID                     string                    `json:"id"`
	IoticsSpecVersion      string                    `json:"ioticsSpecVersion"`
	IoticsDIDType          string                    `json:"ioticsDIDType"` // note: also known as Purpose
	Controller             string                    `json:"controller,omitempty"`
	Creator                string                    `json:"creator,omitempty"`
	UpdateTime             int64                     `json:"updateTime"` // milliseconds
	Proof                  string                    `json:"proof"`
	Revoked                bool                      `json:"revoked,omitempty"`
	AuthenticationKeys     []RegisterPublicKey       `json:"authentication,omitempty"`
	PublicKeys             []RegisterPublicKey       `json:"publicKey"`
	DelegateAuthentication []RegisterDelegationProof `json:"delegateAuthentication,omitempty"`
	DelegateControl        []RegisterDelegationProof `json:"delegateControl,omitempty"`
	Metadata               Metadata                  `json:"metadata,omitempty"`
}

// PublicKeyByID get public key by ID (note: excluding authentication keys).
func (document RegisterDocument) PublicKeyByID(id string) *RegisterPublicKey {
	for _, v := range document.PublicKeys {
		if v.ID == id {
			return &RegisterPublicKey{
				ID:              v.ID,
				Type:            v.Type,
				PublicKeyBase58: v.PublicKeyBase58,
				Revoked:         v.Revoked,
			}
		}
	}

	return nil
}

// Validate Document validation (correct fields, lengths, types etc NOT CRYPTO)
func (document RegisterDocument) Validate() []error {
	var errs []error

	if document.Context != DocumentContext {
		errs = append(errs, fmt.Errorf("document context must be: '%s'", DocumentContext))
	}

	if !specVersionExists(document.IoticsSpecVersion) {
		errs = append(errs, fmt.Errorf("document version should be: '%s'", defaultVersion))
	}

	err := validation.ValidateIdentifier(document.ID)
	if err != nil {
		errs = append(errs, err)
	}

	_, err = identity.ParseDidType(document.IoticsDIDType)
	if err != nil {
		errs = append(errs, err)
	}

	if document.Controller == document.ID {
		errs = append(errs, errors.New("document controller cannot be self"))
	}

	if len(document.Metadata.Label) > maxLabelLength {
		errs = append(errs, fmt.Errorf("metadata label is longer than max %d", maxLabelLength))
	}
	if len(document.Metadata.Comment) > maxCommentLength {
		errs = append(errs, fmt.Errorf("metadata comment is longer than max %d", maxCommentLength))
	}
	if len(document.Metadata.URL) > maxURLLength {
		errs = append(errs, fmt.Errorf("metadata url is longer than max %d", maxURLLength))
	}

	// Check key/delegation names are unique in the document
	bufOfNames := map[string]bool{}

	for _, publicKey := range document.PublicKeys {
		errs = append(errs, validatePublicKey(PublicKeyTypeString, publicKey)...)

		if _, found := bufOfNames[publicKey.ID]; found {
			errs = append(errs, fmt.Errorf("key name '%s' is not unique", publicKey.ID))
			continue
		}
		bufOfNames[publicKey.ID] = true
	}

	for _, publicKey := range document.AuthenticationKeys {
		errs = append(errs, validatePublicKey(AuthenticationKeyTypeString, publicKey)...)

		if _, found := bufOfNames[publicKey.ID]; found {
			errs = append(errs, fmt.Errorf("key name '%s' is not unique", publicKey.ID))
			continue
		}
		bufOfNames[publicKey.ID] = true
	}

	for _, delegation := range append(document.DelegateControl, document.DelegateAuthentication...) {
		err = validation.ValidateKeyName(delegation.ID)
		if err != nil {
			errs = append(errs, err)
		}

		err = validation.ValidateIssuer(delegation.Controller)
		if err != nil {
			errs = append(errs, err)
		}

		if _, found := bufOfNames[delegation.ID]; found {
			errs = append(errs, fmt.Errorf("delegation name '%s' is not unique", delegation.ID))
			continue
		}
		bufOfNames[delegation.ID] = true
	}

	if len(document.PublicKeys)+len(document.Controller) == 0 {
		errs = append(errs, errors.New("must have controller or one public key"))
	}

	return errs
}

func validatePublicKey(expectedType string, publicKey RegisterPublicKey) []error {
	var errs []error

	err := validation.ValidateKeyName(publicKey.ID)
	if err != nil {
		errs = append(errs, err)
	}

	if publicKey.Type != expectedType {
		errs = append(errs, fmt.Errorf("public key ID %s unexpected type", publicKey.ID))
	}

	publicKeyBytes := base58.DecodeAlphabet(publicKey.PublicKeyBase58, base58.BTCAlphabet)
	err = validation.ValidatePublicKey(publicKeyBytes)
	if err != nil {
		errs = append(errs, err)
	}

	return errs
}
