// Copyright (c) IOTIC LABS LIMITED. All rights reserved. Licensed under the Apache License, Version 2.0.

package register

import "errors"


// KeyType number
type KeyType uint

const (
	// PublicKeyType public key type
	PublicKeyType = iota

	// AuthenticationKeyType authentication key type
	AuthenticationKeyType
)

// NewKeyType get KeyType uint given string type
func NewKeyType(value string) (KeyType, error) {
	switch value {
	case PublicKeyTypeString:
		return PublicKeyType, nil
	case AuthenticationKeyTypeString:
		return AuthenticationKeyType, nil
	default:
		return 0, errors.New("invalid key type")
	}
}

// String KeyType to string
func (keyType KeyType) String() string {
	keyTypes := [...]string{
		PublicKeyTypeString,
		AuthenticationKeyTypeString,
	}

	// prevent panicking in case of
	// `keyType` is out of range of KeyType
	if keyType < PublicKeyType || keyType > AuthenticationKeyType {
		return "Unknown"
	}
	return keyTypes[keyType]
}
