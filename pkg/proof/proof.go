// Copyright (c) IOTIC LABS LIMITED. All rights reserved. Licensed under the Apache License, Version 2.0.

package proof

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"encoding/asn1"
	"encoding/base64"
	"errors"
	"fmt"
	"math/big"

	"github.com/Iotic-Labs/iotics-identity-go/v2/pkg/crypto"
)

// Proof struct
type Proof struct {
	IssuerDid  string
	IssuerName string
	Content    []byte
	Signature  string
}

// ecdsaSignature struct to hold R,S needed for ASN1 marshal
type ecdsaSignature struct {
	R, S *big.Int
}

// NewProof builds a proof.
func NewProof(privateKey *ecdsa.PrivateKey, issuerDid string, issuerName string, content []byte) (*Proof, error) {
	if privateKey == nil || privateKey.D == nil || privateKey.PublicKey.Curve == nil {
		return nil, fmt.Errorf("invalid private key")
	}

	digest := sha256.Sum256(content)
	slice := digest[:]

	r, s, err := ecdsa.Sign(rand.Reader, privateKey, slice)
	if err != nil {
		return nil, err
	}

	buf, err := asn1.Marshal(ecdsaSignature{r, s})
	if err != nil {
		return nil, err
	}

	signature := base64.StdEncoding.EncodeToString(buf)
	proof := &Proof{
		IssuerDid:  issuerDid,
		IssuerName: issuerName,
		Content:    content,
		Signature:  signature,
	}
	return proof, nil
}

// ValidateProof validates proof.
// @param proof: proof
// @param public_base58: public key base 58 used to create the proof
func ValidateProof(proof *Proof, publicBase58 string) error {
	der, err := base64.StdEncoding.DecodeString(proof.Signature)
	if err != nil {
		return err
	}

	publicKey, err := crypto.GetPublicKeyFromBase58(publicBase58)
	if err != nil {
		return err
	}
	digest := sha256.Sum256(proof.Content)
	slice := digest[:]

	sig := &ecdsaSignature{}
	_, err = asn1.Unmarshal(der, sig)
	if err != nil {
		return errors.New("unable to decode proof signature") // The err "asn1: structure error: tags don't match"
	}

	valid := ecdsa.Verify(publicKey, slice, sig.R, sig.S)
	if !valid {
		return fmt.Errorf("invalid signature")
	}

	return nil
}
