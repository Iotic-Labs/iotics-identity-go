// Copyright (c) IOTIC LABS LIMITED. All rights reserved. Licensed under the Apache License, Version 2.0.

package register

const (
	// DocumentContext context in document
	DocumentContext = "https://w3id.org/did/v1"

	// PublicKeyTypeString key type string for public key section
	PublicKeyTypeString = "Secp256k1VerificationKey2018"

	// AuthenticationKeyTypeString key type string for authentication section
	AuthenticationKeyTypeString = "Secp256k1SignatureAuthentication2018"
)

// Metadata optional structure on DID Document
type Metadata struct {
	Label   string `json:"label,omitempty"`
	Comment string `json:"comment,omitempty"`
	URL     string `json:"url,omitempty"`
}

// RegisterPublicKey structure for key used in authentication and publicKey in lists
type RegisterPublicKey struct {
	ID              string `json:"id"`
	Type            string `json:"type"`
	PublicKeyBase58 string `json:"publicKeyBase58"`
	Revoked         bool   `json:"revoked,omitempty"`
}

// RegisterDelegationProof structure on delegation
type RegisterDelegationProof struct {
	ID         string `json:"id"`
	Controller string `json:"controller"`
	Proof      string `json:"proof"`
	Revoked    bool   `json:"revoked,omitempty"`
}

// RegisterDocument structure for document data
type RegisterDocument struct {
	Context                string                    `json:"@context"`
	ID                     string                    `json:"id"`
	IoticsSpecVersion      string                    `json:"ioticsSpecVersion"`
	IoticsDIDType          string                    `json:"ioticsDIDType"` // note: also known as Purpose
	Controller             string                    `json:"controller,omitempty"`
	Creator                string                    `json:"creator,omitempty"`
	UpdateTime             int64                     `json:"updateTime"`
	Proof                  string                    `json:"proof"`
	Revoked                bool                      `json:"revoked,omitempty"`
	AuthenticationKeys     []RegisterPublicKey       `json:"authentication,omitempty"`
	PublicKeys             []RegisterPublicKey       `json:"publicKey"`
	DelegateAuthentication []RegisterDelegationProof `json:"delegateAuthentication,omitempty"`
	DelegateControl        []RegisterDelegationProof `json:"delegateControl,omitempty"`
	Metadata               Metadata                  `json:"metadata,omitempty"`
}

// PublicKeyByName get public key by name (note: excluding authentication keys)
func (d RegisterDocument) PublicKeyByName(name string) *RegisterPublicKey {
	for _, v := range d.PublicKeys {
		if v.Name() == name {
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
