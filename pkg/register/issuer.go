// Copyright (c) IOTIC LABS LIMITED. All rights reserved. Licensed under the Apache License, Version 2.0.

package register

import (
	"fmt"
	"strings"

	"github.com/Iotic-Labs/iotics-identity-go/v2/pkg/validation"
	"github.com/golang-jwt/jwt"
)

var defaultSigningMethod = jwt.SigningMethodES256

// Issuer struct
type Issuer struct {
	Did  string
	Name string
}

// String returns the object as a string.
func (i Issuer) String() string {
	return fmt.Sprintf("%s%s", i.Did, i.Name)
}

// NewIssuer creates a valid issuer or returns an error.
func NewIssuer(did string, name string) (*Issuer, error) {
	if err := validation.ValidateIdentifier(did); err != nil {
		return nil, err
	}
	if err := validation.ValidateKeyName(name); err != nil {
		return nil, err
	}
	result := &Issuer{
		Did:  did,
		Name: name,
	}
	return result, nil
}

// NewIssuerFromString creates a valid issuer from issuer string or returns an error.
func NewIssuerFromString(issuerString string) (*Issuer, error) {
	parts := strings.Split(issuerString, validation.IssuerSeparator)
	if len(parts) != 2 {
		return nil, fmt.Errorf("invalid issuer string '%s' should be of the form [did]%s[name]", issuerString, validation.IssuerSeparator)
	}
	return NewIssuer(parts[0], fmt.Sprintf("%s%s", validation.IssuerSeparator, parts[1]))
}

// IssuerKey combines Issuer and public key base58 string
type IssuerKey struct {
	Issuer          *Issuer
	PublicKeyBase58 string
}

// NewIssuerKey builds an issuer key from identifier, name and public key.
func NewIssuerKey(did string, name string, publicKeyBase58 string) (*IssuerKey, error) {
	issuer, err := NewIssuer(did, name)
	if err != nil {
		return nil, err
	}
	result := &IssuerKey{
		Issuer:          issuer,
		PublicKeyBase58: publicKeyBase58,
	}
	return result, nil
}
