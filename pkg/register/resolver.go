// Copyright (c) IOTIC LABS LIMITED. All rights reserved. Licensed under the Apache License, Version 2.0.

package register

import (
	"context"
	"crypto/ecdsa"
	"errors"
)

// ResolverClient resolver client interface
type ResolverClient interface {
	// GetDocument fetch a document from the resolver by DID identifier
	GetDocument(ctx context.Context, documentID string) (*RegisterDocument, error)

	// RegisterDocument registers a document in the resolver.
	RegisterDocument(ctx context.Context, doc *RegisterDocument, privateKey *ecdsa.PrivateKey, issuer *Issuer) error
}

// ResolverErrType ResolverErrType
type ResolverErrType int

const (
	// ConfError Resolver configuration error type
	ConfError ResolverErrType = iota
	// ConnectionError Resolver connection error type
	ConnectionError
	// ServerError Resolver server error type
	ServerError
	// NotFound Resolver did not found error type
	NotFound
)

// ResolverError type, implements the error interface
type ResolverError struct {
	err     error
	errType ResolverErrType
}

// NewResolverError Create a new error (For tests)
func NewResolverError(err error, errType ResolverErrType) error {
	return &ResolverError{err: err, errType: errType}
}

// Error returns the representation
func (r ResolverError) Error() string {
	if r.err == nil {
		return "resolver error"
	}
	return r.err.Error()
}

// ErrorType returns the error type
func (r ResolverError) ErrorType() ResolverErrType {
	return r.errType
}

// Err returns the err
func (r ResolverError) Err() error {
	return r.err
}

// IsResolverError returns true if the provided error is of type ResolverError
func IsResolverError(err error) bool {
	_, ok := err.(*ResolverError)
	return ok
}

// IsContextError returns true if the provided error is of type context.Canceled or context.DeadlineExceeded
func IsContextError(err error) bool {
	return errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded)
}
