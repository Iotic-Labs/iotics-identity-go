// Copyright (c) IOTIC LABS LIMITED. All rights reserved. Licensed under the Apache License, Version 2.0.

package register

import (
	"context"
	"crypto/ecdsa"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"

	// "os/exec"
	"strings"
	"time"

	"github.com/Iotic-Labs/iotics-identity-go/v3/pkg/validation"
)

var defaultResolverTimeout = time.Second * 60

// RestResolverClient REST Resolver struct
type RestResolverClient struct {
	url    *url.URL
	client *http.Client
}

// NewDefaultRestResolverClient build a new REST Resolver Client with default HTTP timeout
func NewDefaultRestResolverClient(url *url.URL) ResolverClient {
	return NewRestResolverClient(url, defaultResolverTimeout)
}

// NewRestResolverClient build a new REST Resolver Client
func NewRestResolverClient(url *url.URL, timeout time.Duration) ResolverClient {
	return NewRestResolverClientWithCustomClient(
		url,
		&http.Client{
			Timeout: timeout,
			Transport: &http.Transport{
				// Since only using a single URL, use equal limits
				MaxIdleConnsPerHost: 2,
				MaxIdleConns:        2,
				// Re-use should only apply when making many repeated calls in quick succession.
				IdleConnTimeout: 5 * time.Second,
			},
		},
	)
}

// NewRestResolverClientWithCustomClient build a ResolverClient with customer http.Client
func NewRestResolverClientWithCustomClient(url *url.URL, client *http.Client) ResolverClient {
	return &RestResolverClient{
		url:    url,
		client: client,
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
func (c *RestResolverClient) GetDocument(ctx context.Context, documentID string) (*RegisterDocument, error) {
	err := validation.ValidateIdentifier(documentID)
	if err != nil {
		return nil, err
	}

	discoverURL := fmt.Sprintf("%s/1.0/discover/%s", c.url.String(), url.QueryEscape(documentID))

	reqWithContext, err := http.NewRequestWithContext(ctx, http.MethodGet, discoverURL, nil)
	if err != nil {
		return nil, &ResolverError{err: err, errType: ServerError}
	}
	response, err := c.client.Do(reqWithContext)

	if err != nil {
		if IsContextError(err) {
			return nil, err
		}

		neterr, ok := err.(net.Error)
		if ok && neterr.Timeout() {
			totalResolverErrors.WithLabelValues(MetricErrorTypeTimeout).Inc()
		} else {
			totalResolverErrors.WithLabelValues(MetricErrorTypeConnection).Inc()
		}
		return nil, &ResolverError{err: err, errType: ConnectionError}
	}
	defer response.Body.Close()

	if response.StatusCode == http.StatusNotFound {
		totalResolverErrors.WithLabelValues(MetricErrorTypeNotFound).Inc()
		return nil, &ResolverError{err: fmt.Errorf("%s: document %s", http.StatusText(http.StatusNotFound), documentID), errType: NotFound}
	}

	data, err := io.ReadAll(response.Body)
	if err != nil {
		neterr, ok := err.(net.Error)
		if ok && neterr.Timeout() {
			totalResolverErrors.WithLabelValues(MetricErrorTypeTimeout).Inc()
		} else {
			totalResolverErrors.WithLabelValues(MetricErrorTypeServer).Inc()
		}
		return nil, &ResolverError{err: err, errType: ConnectionError}
	}

	var resp map[string]interface{}
	if err := json.Unmarshal(data, &resp); err != nil {
		totalResolverErrors.WithLabelValues(MetricErrorTypeServer).Inc()
		return nil, &ResolverError{err: err, errType: ServerError}
	}

	// For certain error cases body of response can contain additional information (resp[error])
	errMsg := http.StatusText(response.StatusCode)
	if response.StatusCode != http.StatusOK {
		totalResolverErrors.WithLabelValues(MetricErrorTypeServer).Inc()
		if errDetail, found := resp["error"]; found {
			errMsg += fmt.Sprintf(": %s", errDetail)
		}
		return nil, &ResolverError{err: errors.New(errMsg), errType: ServerError}
	}

	// Verify the document using ourselves
	claims, err := DecodeDocumentTokenNoVerify(JwtToken(resp["token"].(string))) // TODO: Must verify here !!

	if err != nil {
		return nil, err
	}
	return claims.Doc, err
}

// RegisterDocument registers a document in the resolver.
func (c *RestResolverClient) RegisterDocument(ctx context.Context, document *RegisterDocument, privateKey *ecdsa.PrivateKey, issuer *Issuer) error {
	token, err := CreateDocumentToken(issuer, c.url.String(), document, privateKey)
	if err != nil {
		return err
	}

	registerURL := fmt.Sprintf("%s/1.0/register", c.url.String())

	bodyReader := strings.NewReader(string(token))
	reqWithContext, err := http.NewRequestWithContext(ctx, http.MethodPost, registerURL, bodyReader)
	if err != nil {
		return &ResolverError{err: err, errType: ServerError}
	}
	response, err := c.client.Do(reqWithContext)

	if err != nil {
		if IsContextError(err) {
			return err
		}
		neterr, ok := err.(net.Error)
		if ok && neterr.Timeout() {
			totalResolverErrors.WithLabelValues(MetricErrorTypeTimeout).Inc()
		} else {
			totalResolverErrors.WithLabelValues(MetricErrorTypeConnection).Inc()
		}
		return &ResolverError{err: err, errType: ConnectionError}
	}
	defer response.Body.Close()

	data, err := io.ReadAll(response.Body)
	if err != nil {
		if IsContextError(err) {
			return err
		}
		neterr, ok := err.(net.Error)
		if ok && neterr.Timeout() {
			totalResolverErrors.WithLabelValues(MetricErrorTypeTimeout).Inc()
		} else {
			totalResolverErrors.WithLabelValues(MetricErrorTypeServer).Inc()
		}
		return &ResolverError{err: err, errType: ConnectionError}
	}

	if response.StatusCode == http.StatusCreated || response.StatusCode == http.StatusOK {
		return nil
	}

	errMsg := http.StatusText(response.StatusCode)

	var resp map[string]interface{}
	if err := json.Unmarshal(data, &resp); err == nil {
		if errDetail, found := resp["error"]; found {
			errMsg += fmt.Sprintf(": %s", errDetail)
		}
	}
	totalResolverErrors.WithLabelValues(MetricErrorTypeServer).Inc()
	return &ResolverError{err: errors.New(errMsg), errType: ServerError}
}
