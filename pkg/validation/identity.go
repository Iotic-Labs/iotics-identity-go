// Copyright (c) IOTIC LABS LIMITED. All rights reserved. Licensed under the Apache License, Version 2.0.

package validation

import (
	"crypto/elliptic"
	"encoding/hex"
	"fmt"
	"regexp"
	"strings"

	"github.com/fomichev/secp256k1"
	"github.com/jbenet/go-base58"

	"golang.org/x/crypto/blake2b"
)

var (
	didIdentifierPattern = fmt.Sprintf(`%siot(?P<hash>[a-km-zA-HJ-NP-Z1-9]{33})`, IdentifierPrefix)
	issuerPattern        = fmt.Sprintf(`%s\#%s`, didIdentifierPattern, NamePattern)
	keyNamePattern       = fmt.Sprintf(`\%s%s`, IssuerSeparator, NamePattern)

	validDidIdentifier, _ = regexp.Compile(fmt.Sprintf(`^%s$`, didIdentifierPattern))
	validIssuer, _        = regexp.Compile(fmt.Sprintf(`^%s$`, issuerPattern))
	validKeyName, _       = regexp.Compile(fmt.Sprintf(`^%s$`, keyNamePattern))
)

// ValidateIdentifier validates decentralised identifier.
// @param did: decentralised identifier
func ValidateIdentifier(did string) error {
	if !validDidIdentifier.Match([]byte(did)) {
		return fmt.Errorf("invalid identifier '%s' does not match pattern '%s", did, validDidIdentifier.String())
	}

	didBytes := base58.DecodeAlphabet(did[len(IdentifierPrefix):], base58.BTCAlphabet)
	didDigest, _ := Blake2bSum160(didBytes[3:23])
	didDigestHex := hex.EncodeToString(didDigest)
	didChecksum := hex.EncodeToString(didBytes[23:27])

	if !strings.HasPrefix(didDigestHex, didChecksum) {
		return fmt.Errorf("invalid identifier '%s' checksum does not match '%s' != '%s", did, didDigestHex, didChecksum)
	}

	return nil
}

// ValidateIssuer validates issuer
func ValidateIssuer(issuer string) error {
	if validIssuer.Match([]byte(issuer)) {
		return nil
	}
	return fmt.Errorf("invalid issuer '%s' does not match pattern '%s", issuer, validIssuer.String())
}

// ValidatePublicKey validated public key bytes are valid public key
func ValidatePublicKey(publicKeyBytes []byte) error {
	if len(publicKeyBytes) != 65 {
		return fmt.Errorf("public key bytes wrong length %d != 65", len(publicKeyBytes))
	}
	if publicKeyBytes[0] != 4 {
		return fmt.Errorf("public key bytes not in uncompressed format")
	}

	curve := secp256k1.SECP256K1()
	x, _ := elliptic.Unmarshal(curve, publicKeyBytes)
	if x == nil {
		return fmt.Errorf("invalid secp256k1 public key")
	}

	return nil
}

// ValidateKeyName validates key name.
func ValidateKeyName(keyName string) error {
	if validKeyName.Match([]byte(keyName)) {
		return nil
	}
	return fmt.Errorf("invalid name '%s' does not match pattern '%s", keyName, validKeyName.String())
}

// Blake2bSum160 Helper function to make blame2b.Sum160
func Blake2bSum160(src []byte) ([]byte, error) {
	digest, err := blake2b.New(20, []byte(""))
	if err != nil {
		return nil, err
	}

	_, err = digest.Write([]byte(src))
	if err != nil {
		return nil, err
	}

	sum := digest.Sum([]byte(""))
	return sum, nil
}
