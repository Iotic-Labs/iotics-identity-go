// Copyright (c) IOTIC LABS LIMITED. All rights reserved. Licensed under the Apache License, Version 2.0.

package identity

import (
	"fmt"
	"strings"

	"github.com/Iotic-Labs/iotics-identity-go/v3/pkg/validation"
	"github.com/jbenet/go-base58"
)

const (
	methodByte  = 0x05
	versionByte = 0x55
	padByte     = 0x59
	checksumLen = 4
)

// IsSameIdentifier checks if 2 issuers string have the same identifier
func IsSameIdentifier(issuerA string, issuerB string) bool {
	return strings.Split(issuerA, validation.IssuerSeparator)[0] == strings.Split(issuerB, validation.IssuerSeparator)[0]
}

// MakeIdentifier generates a new decentralised identifier from public key as bytes.
func MakeIdentifier(publicKeyBytes []byte) (string, error) {
	err := validation.ValidatePublicKey(publicKeyBytes)
	if err != nil {
		return "", err
	}

	// Method A - Identifier from public key bytes
	// base58 ( METHOD + VERSION + PAD + blake2(pubkey).bytes() + blake2(blake2(pubkey)).bytes()[:4] )
	pkDigest, _ := validation.Blake2bSum160(publicKeyBytes)
	chkDigest, _ := validation.Blake2bSum160(pkDigest)
	chkDigestTrunc := chkDigest[:checksumLen]

	pad := make([]byte, 3)
	pad[0] = methodByte
	pad[1] = versionByte
	pad[2] = padByte
	first := append(pad, pkDigest...)
	full := append(first, chkDigestTrunc...)

	encoded := base58.EncodeAlphabet(full, base58.BTCAlphabet)
	return validation.IdentifierPrefix + encoded, nil
}

// MakeName make a valid key name given DID Type
func MakeName(purpose DidType) string {
	return fmt.Sprintf("%s%s-0", validation.IssuerSeparator, purpose.String())
}
