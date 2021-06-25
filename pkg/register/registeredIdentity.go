// Copyright (c) IOTIC LABS LIMITED. All rights reserved. Licensed under the Apache License, Version 2.0.

package register

import (
	"github.com/Iotic-Labs/iotics-identity-go/pkg/crypto"
)

// RegisteredIdentity interface
type RegisteredIdentity interface {
	Did() string
	Name() string
	KeyPair() *crypto.KeyPair
	Issuer() *Issuer
}

//
type defaultRegisteredIdentity struct {
	keyPair *crypto.KeyPair
	issuer  *Issuer
}

// NewRegisteredIdentity New RegisteredIdentity
func NewRegisteredIdentity(keyPair *crypto.KeyPair, issuer *Issuer) RegisteredIdentity {
	return &defaultRegisteredIdentity{
		keyPair: keyPair,
		issuer:  issuer,
	}
}

func (i *defaultRegisteredIdentity) Did() string {
	return i.issuer.Did // todo: risk of nil reference
}

func (i *defaultRegisteredIdentity) Name() string {
	return i.issuer.Name // todo: risk of nil reference
}

func (i *defaultRegisteredIdentity) KeyPair() *crypto.KeyPair {
	return i.keyPair
}

func (i *defaultRegisteredIdentity) Issuer() *Issuer {
	return i.issuer
}
