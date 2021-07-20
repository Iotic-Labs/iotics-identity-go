// Copyright (c) IOTIC LABS LIMITED. All rights reserved. Licensed under the Apache License, Version 2.0.

package test

import (
	"crypto/ecdsa"
	"fmt"
	"sync"

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
	c.documents[document.ID] = document
	return nil
}
