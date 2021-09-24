// Copyright (c) IOTIC LABS LIMITED. All rights reserved. Licensed under the Apache License, Version 2.0.

package identity

import "fmt"

// DidType is the DID document type string eg (user, agent, twin ...)
type DidType uint

const (
	Host DidType = iota
	User
	Agent
	Twin
)

// String DidType to string
func (didType DidType) String() string {
	keyTypes := [...]string{
		"host",
		"user",
		"agent",
		"twin",
	}

	// prevent panicking in case of
	// `keyType` is out of range of KeyType
	if didType < Host || didType > Twin {
		return "Unknown"
	}
	return keyTypes[didType]
}

// ParseDidType translate a DID type in string (eg "user") to internal type
func ParseDidType(didType string) (DidType, error) {
	switch didType {
	case "host":
		return Host, nil
	case "user":
		return User, nil
	case "agent":
		return Agent, nil
	case "twin":
		return Twin, nil
	}
	return 0, fmt.Errorf("could not parse DidType: \"%s\"", didType)
}
