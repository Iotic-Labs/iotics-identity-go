// Copyright (c) IOTIC LABS LIMITED. All rights reserved. Licensed under the Apache License, Version 2.0.

package validation

const (
	// IssuerSeparator constant separator between DID identifier and name
	IssuerSeparator = "#"

	// IdentifierPrefix constant prefix for Iotics DID identifiers
	IdentifierPrefix = "did:iotics:"

	// IoticsPathPrefix Iotics path prefix used for deterministic keys
	IoticsPathPrefix = "iotics/0"

	// NamePattern regular expression for DID key names
	NamePattern = "[a-zA-Z\\-\\_0-9]{1,24}"
)
