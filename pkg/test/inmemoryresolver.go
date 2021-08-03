// Copyright (c) IOTIC LABS LIMITED. All rights reserved. Licensed under the Apache License, Version 2.0.

package test

import (
	"crypto/ecdsa"
	"errors"
	"fmt"
	"sync"

	"github.com/Iotic-Labs/iotics-identity-go/pkg/advancedapi"
	"github.com/Iotic-Labs/iotics-identity-go/pkg/register"
)

type InMemoryResolver struct {
	documents map[string]*register.RegisterDocument
	lock      *sync.RWMutex
}

func NewInMemoryResolver(docs ...*register.RegisterDocument) *InMemoryResolver {
	documents := map[string]*register.RegisterDocument{}
	for _, v := range docs {
		documents[v.ID] = v
	}
	return &InMemoryResolver{
		documents: documents,
		lock:      &sync.RWMutex{},
	}
}

func (c InMemoryResolver) GetDocument(documentId string) (*register.RegisterDocument, error) {
	c.lock.RLock()
	defer c.lock.RUnlock()
	v, exists := c.documents[documentId]
	if exists {
		return v, nil
	}
	return nil, fmt.Errorf("document not found")
}

func (c InMemoryResolver) RegisterDocument(document *register.RegisterDocument, _ *ecdsa.PrivateKey, _ *register.Issuer) error {
	c.lock.Lock()
	defer c.lock.Unlock()

	errs := document.Validate()
	if len(errs) != 0 {
		errStr := "unable to verify document: "
		for _, err := range errs {
			errStr = fmt.Sprintf("%s, %s", errStr, err)
		}
		return errors.New(errStr)
	}

	// The resolver will run this check.  It results in an infinite loop in unit tests.
	// There is a problem in a unit test somewhere, probably delegation to self causing infinite loop
	// fixme: err = advancedapi.ValidateRegisterDocument(c, document)

	if _, found := c.documents[document.ID]; found {
		if c.documents[document.ID].UpdateTime > document.UpdateTime {
			// Note: This check should be >= (as resolver) but most tests run so fast the millis is the same
			// so we just have a basic protection here, cannot register old doc over new.
			return errors.New("update time must be newer")
		}
	} else {
		err := advancedapi.ValidateDocumentProof(document)
		if err != nil {
			return err
		}
	}

	c.documents[document.ID] = document
	return nil
}
