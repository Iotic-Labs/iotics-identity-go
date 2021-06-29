// Copyright (c) IOTIC LABS LIMITED. All rights reserved. Licensed under the Apache License, Version 2.0.

package api

import (
	"github.com/Iotic-Labs/iotics-identity-go/pkg/crypto"
	"github.com/Iotic-Labs/iotics-identity-go/pkg/register"
)

type CreateUserAndAgentWithAuthDelegationOpts struct {
	UserSeed       []byte
	UserKeyName    string
	UserName       string
	UserPassword   string
	AgentSeed      []byte
	AgentKeyName   string
	AgentName      string
	AgentPassword  string
	DelegationName string
	OverrideDocs   bool
}

type CreateIdentityOpts struct {
	Seed     []byte
	KeyName  string
	Password string
	Name     string
	Method   crypto.SeedMethod
	Override bool
}

type CreateTwinOpts struct {
	Seed           []byte
	KeyName        string
	Name           string
	Password       string
	AgentId        register.RegisteredIdentity
	DelegationName string
	OverideDoc     bool
}

type GetIdentityOpts struct {
	Did      string
	Seed     []byte
	KeyName  string
	Password string
	Name     string
	Method   crypto.SeedMethod
}

type GetKeyPairOpts struct {
	Seed     []byte
	KeyName  string
	Password string
	Method   crypto.SeedMethod
}
