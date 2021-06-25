// Copyright (c) IOTIC LABS LIMITED. All rights reserved. Licensed under the Apache License, Version 2.0.

package register

import "fmt"

// KeyType number
type KeyType uint

const (
	// PublicKeyType public key type
	PublicKeyType = iota

	// AuthenticationKeyType authentication key type
	AuthenticationKeyType
)

const (
	// key type string for public key section
	publicKeyTypeString = "Secp256k1VerificationKey2018"
	// key type string for authentication section
	authenticationKeyTypeString = "Secp256k1SignatureAuthentication2018"
)

// NewKeyType get KeyType uint given string type
func NewKeyType(value string) (KeyType, error) {
	switch value {
	case publicKeyTypeString:
		return PublicKeyType, nil
	case authenticationKeyTypeString:
		return AuthenticationKeyType, nil
	default:
		return 0, fmt.Errorf("invalid key type")
	}
}

// String KeyType to string
func (keyType KeyType) String() string {
	keyTypes := [...]string{
		publicKeyTypeString,
		authenticationKeyTypeString,
	}

	// prevent panicking in case of
	// `keyType` is out of range of KeyType
	if keyType < PublicKeyType || keyType > AuthenticationKeyType {
		return "Unknown"
	}
	return keyTypes[keyType]
}
