// Copyright (c) IOTIC LABS LIMITED. All rights reserved. Licensed under the Apache License, Version 2.0.

package api

import (
	"github.com/Iotic-Labs/iotics-identity-go/pkg/crypto"
	"github.com/Iotic-Labs/iotics-identity-go/pkg/register"
)

// CreateUserAndAgentWithAuthDelegationOpts Create user and agent options for high level API
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

// CreateTwinOpts Create twin options (with agent delegation) for highlevel API
type CreateTwinOpts struct {
	Seed           []byte
	KeyName        string
	Name           string
	Password       string
	AgentID        register.RegisteredIdentity
	AgentDoc       *register.RegisterDocument
	DelegationName string
	Override       bool
}

// CreateIdentityOpts Create identity options for regular API
type CreateIdentityOpts struct {
	Seed     []byte
	KeyName  string
	Password string
	Name     string
	Method   crypto.SeedMethod
	Override bool
}

// GetIdentityOpts get identity options for regular API
type GetIdentityOpts struct {
	Did      string
	Seed     []byte
	KeyName  string
	Password string
	Name     string
	Method   crypto.SeedMethod
}

// GetKeyPairOpts get key pair options for regular API
type GetKeyPairOpts struct {
	Seed     []byte
	KeyName  string
	Password string
	Method   crypto.SeedMethod
}
