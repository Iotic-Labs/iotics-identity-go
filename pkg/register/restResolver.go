// Copyright (c) IOTIC LABS LIMITED. All rights reserved. Licensed under the Apache License, Version 2.0.

package register

import (
	"crypto/ecdsa"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/Iotic-Labs/iotics-identity-go/pkg/validation"
)

var defaultResolverTimeout = time.Second * 60

// RestResolverClient REST Resolver struct
type RestResolverClient struct {
	url     *url.URL
	timeout time.Duration
}

// NewDefaultRestResolverClient build a new REST Resolver Client with default HTTP timeout
func NewDefaultRestResolverClient(url *url.URL) ResolverClient {
	return NewRestResolverClient(url, defaultResolverTimeout)
}

// NewRestResolverClient build a new REST Resolver Client
func NewRestResolverClient(url *url.URL, timeout time.Duration) ResolverClient {
	return &RestResolverClient{
		url:     url,
		timeout: timeout,
	}
}

// GetResolverFromEnv lookup RESOLVER from environment
func GetResolverFromEnv() (string, error) {
	result := os.Getenv("RESOLVER")
	if result == "" {
		return "", &ResolverError{err: fmt.Errorf("RESOLVER Environment Variable must be set"),
			errType: ConfError}
	}
	return result, nil
}

// GetDocument fetch a document from the resolver by DID identifier
func (c *RestResolverClient) GetDocument(documentID string) (*RegisterDocument, error) {
	err := validation.ValidateIdentifier(documentID)
	if err != nil {
		return nil, err
	}

	discoverURL := fmt.Sprintf("%s/1.0/discover/%s", c.url.String(), url.QueryEscape(documentID)) // todo: join path?
	client := http.Client{
		Timeout: c.timeout,
	}
	response, err := client.Get(discoverURL)
	if err != nil {
		neterr, ok := err.(net.Error)
		if ok && neterr.Timeout() {
			totalResolverErrors.WithLabelValues(MetricErrorTypeTimeout).Inc()
		} else {
			totalResolverErrors.WithLabelValues(MetricErrorTypeConnection).Inc()
		}
		return nil, &ResolverError{err: err, errType: ConnectionError}
	}

	if response.StatusCode == http.StatusNotFound {
		totalResolverErrors.WithLabelValues(MetricErrorTypeNotFound).Inc()
		return nil, &ResolverError{err: err, errType: NotFound}
	}

	if response.StatusCode != http.StatusOK {
		totalResolverErrors.WithLabelValues(MetricErrorTypeServer).Inc()
		return nil, &ResolverError{err: err, errType: ServerError}
	}

	data, err := ioutil.ReadAll(response.Body)
	if err != nil {
		neterr, ok := err.(net.Error)
		if ok && neterr.Timeout() {
			totalResolverErrors.WithLabelValues(MetricErrorTypeTimeout).Inc()
		} else {
			totalResolverErrors.WithLabelValues(MetricErrorTypeServer).Inc()
		}
		return nil, err
	}

	var resp map[string]interface{}
	if err := json.Unmarshal(data, &resp); err != nil {
		totalResolverErrors.WithLabelValues(MetricErrorTypeServer).Inc()
		return nil, err
	}

	// Verify the document using ourselves
	claims, err := DecodeDocumentTokenNoVerify(JwtToken(resp["token"].(string))) // TODO: Must verify here !!
	if err != nil {
		return nil, err
	}
	return claims.Doc, err
}

// RegisterDocument registers a document in the resolver.
func (c *RestResolverClient) RegisterDocument(document *RegisterDocument, privateKey *ecdsa.PrivateKey, issuer *Issuer) error {
	token, err := CreateDocumentToken(issuer, c.url.String(), document, privateKey)
	if err != nil {
		return err
	}

	client := http.Client{
		Timeout: c.timeout,
	}
	registerURL := fmt.Sprintf("%s/1.0/register", c.url.String())
	rdr := strings.NewReader(string(token))
	response, err := client.Post(registerURL, "text/plain", rdr) // FIXME content type
	if err != nil {
		neterr, ok := err.(net.Error)
		if ok && neterr.Timeout() {
			totalResolverErrors.WithLabelValues(MetricErrorTypeTimeout).Inc()
		} else {
			totalResolverErrors.WithLabelValues(MetricErrorTypeConnection).Inc()
		}
		return &ResolverError{err: err, errType: ConnectionError}
	}

	if response.StatusCode != http.StatusCreated && response.StatusCode != http.StatusOK {
		totalResolverErrors.WithLabelValues(MetricErrorTypeServer).Inc()
		return &ResolverError{err: err, errType: ServerError}
	}

	data, err := ioutil.ReadAll(response.Body)
	if err != nil {
		neterr, ok := err.(net.Error)
		if ok && neterr.Timeout() {
			totalResolverErrors.WithLabelValues(MetricErrorTypeTimeout).Inc()
		} else {
			totalResolverErrors.WithLabelValues(MetricErrorTypeServer).Inc()
		}
		return err
	}

	var resp map[string]interface{}
	if err := json.Unmarshal(data, &resp); err != nil {
		totalResolverErrors.WithLabelValues(MetricErrorTypeServer).Inc()
		return err
	}

	return nil
}
