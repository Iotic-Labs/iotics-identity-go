// Copyright (c) IOTIC LABS LIMITED. All rights reserved. Licensed under the Apache License, Version 2.0.

package register_test

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"testing"

	"github.com/Iotic-Labs/iotics-identity-go/v3/pkg/test"

	"github.com/jarcoal/httpmock"
	"gotest.tools/assert"

	"github.com/Iotic-Labs/iotics-identity-go/v3/pkg/register"
)

var (
	// 'agent1'
	ValidID    = "did:iotics:iotYJuJs2V31BHc5HvVRM3Aa5T2BD5Q9v3Rq"
	ValidToken = "eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NiJ9.eyJpc3MiOiJkaWQ6aW90aWNzOmlvdFlKdUpzMlYzMUJIYzVIdlZSTTNBYTVUMkJENVE5djNScSNhZ2VudC0wIiwiYXVkIjoibW9jazovL3Jlc29sdmVyIiwiZG9jIjp7IkBjb250ZXh0IjoiaHR0cHM6Ly93M2lkLm9yZy9kaWQvdjEiLCJpZCI6ImRpZDppb3RpY3M6aW90WUp1SnMyVjMxQkhjNUh2VlJNM0FhNVQyQkQ1UTl2M1JxIiwiaW90aWNzU3BlY1ZlcnNpb24iOiIwLjAuMSIsImlvdGljc0RJRFR5cGUiOiJhZ2VudCIsInVwZGF0ZVRpbWUiOjE2MDI0OTgyOTc5MjcsInByb29mIjoiTUVVQ0lRQ0xFNWZVdWlTVXZvbklEaEUzT1ZIcXY2cVNuK1UxdFY4RFNleHpaMHl4M1FJZ2FyV3pONzFsaTlLU3VBOHhMUWg3NmpkSkJHN1QyRUEwMjJMbnFnR1hxUDA9IiwicHVibGljS2V5IjpbeyJpZCI6IiNhZ2VudC0wIiwidHlwZSI6IlNlY3AyNTZrMVZlcmlmaWNhdGlvbktleTIwMTgiLCJwdWJsaWNLZXlCYXNlNTgiOiJSR2p6TDU4Zmd4dlZxR1Iyam5YRWZCZlMzV3g0ZHZNQnR4NzRRWXBObUN4dHdGeDJtNTZxSlBkeU5Xa1Z3dVBSOGs2WlB2dTI5N1Z6aTlDWVNQdTdpMmdoIiwicmV2b2tlZCI6ZmFsc2V9XSwiYXV0aGVudGljYXRpb24iOltdLCJkZWxlZ2F0ZUNvbnRyb2wiOltdLCJkZWxlZ2F0ZUF1dGhlbnRpY2F0aW9uIjpbXSwibWV0YWRhdGEiOnt9fX0.CHl_30AhfFe-Cfny8axwdmZ_iF4nhFFxUsm0rcMJIQGCrN3X-HcSX60X7x2IDVM4Sbw-JGbgpgZ6QRJJyhxYTA"
)

type testKey string

func init() {
	httpmock.Activate()
}

type TestResolverMetrics struct {
	// resolver client metrics
	ResolverClientNotFoundErrors      int
	ResolverClientServerErrors        int
	ResolverClientConnections         int
	ResolverClientConnectionsReleased int
}

// NewTestResolverMetrics returns a new TestResolverMetrics instance
func NewTestResolverMetrics() *TestResolverMetrics {
	return &TestResolverMetrics{
		ResolverClientNotFoundErrors:      0,
		ResolverClientServerErrors:        0,
		ResolverClientConnections:         0,
		ResolverClientConnectionsReleased: 0,
	}
}

// RecordError registers a new error to the resolver
func (t *TestResolverMetrics) RecordError(errType register.ResolverErrType) {
	switch errType {
	case register.ServerError:
		t.ResolverClientServerErrors++
	case register.NotFound:
		t.ResolverClientNotFoundErrors++
	default:
		panic(fmt.Sprintf("unknown error type %s", errType))
	}
}

// RecordConnection registers a new connection to the resolver
func (t *TestResolverMetrics) RecordConnection() {
	t.ResolverClientConnections++
}

// RecordConnectionReleased registers a connection released from the resolver
func (t *TestResolverMetrics) RecordConnectionReleased() {
	t.ResolverClientConnectionsReleased++
}

func Test_Resolver_Successful_Get(t *testing.T) {
	var contextKey testKey = "test_key"
	contextValue := "test_value"
	ctx := context.WithValue(context.TODO(), contextKey, contextValue)

	addr, _ := url.Parse("http://localhost:9034")

	metrics := NewTestResolverMetrics()
	// Setup a resolver client with metrics
	// Note: Passing in http.DefaultClient since by default, e.g. via NewDefaultRestResolverClient, a new http.Client
	// instance is used. httpmock however expects to work against the default client, unless using
	// httpmock.ActivateNonDefault().
	rslv := register.NewMeteredRestResolverClient(addr, http.DefaultClient, metrics)

	// Setup a mock resolver
	discoverReply := map[string]interface{}{
		"token": ValidToken,
	}
	httpmock.RegisterResponder("GET", addr.String()+"/1.0/discover/"+url.QueryEscape(ValidID),
		func(req *http.Request) (*http.Response, error) {
			// Check context is passed through
			assert.Equal(t, req.Context().Value(contextKey), contextValue)
			return httpmock.NewJsonResponse(http.StatusOK, discoverReply)
		},
	)

	// Place the call
	_, err := rslv.GetDocument(ctx, ValidID)
	assert.NilError(t, err)

	// Check metrics
	assert.Equal(t, metrics.ResolverClientConnections, 1)
	assert.Equal(t, metrics.ResolverClientConnectionsReleased, 1)
	assert.Equal(t, metrics.ResolverClientNotFoundErrors, 0)
	assert.Equal(t, metrics.ResolverClientServerErrors, 0)
}

func Test_Resolver_Notfound_Error(t *testing.T) {
	var contextKey testKey = "test_key"
	contextValue := "test_value"
	ctx := context.WithValue(context.TODO(), contextKey, contextValue)

	addr, _ := url.Parse("http://localhost:9044")

	metrics := NewTestResolverMetrics()
	// Setup a resolver client with metrics
	rslv := register.NewMeteredRestResolverClient(addr, http.DefaultClient, metrics)

	// Setup a mock resolver
	discoverReply := map[string]interface{}{
		"error": "Notfound",
	}

	httpmock.RegisterResponder("GET", addr.String()+"/1.0/discover/"+url.QueryEscape(ValidID),
		func(req *http.Request) (*http.Response, error) {
			// Check context is passed through
			assert.Equal(t, req.Context().Value(contextKey), contextValue)
			return httpmock.NewJsonResponse(http.StatusNotFound, discoverReply)
		},
	)

	// Place the call
	_, err := rslv.GetDocument(ctx, ValidID)

	assert.Assert(t, register.IsResolverError(err))
	re := err.(*register.ResolverError)
	assert.Equal(t, re.ErrorType(), register.NotFound)
	assert.Assert(t, re.Err() != nil)
	assert.ErrorContains(t, re.Err(), fmt.Sprintf("document %s", ValidID))
	assert.ErrorContains(t, re.Err(), http.StatusText(http.StatusNotFound))

	// Check metrics
	assert.Equal(t, metrics.ResolverClientConnections, 1)
	assert.Equal(t, metrics.ResolverClientConnectionsReleased, 1)
	assert.Equal(t, metrics.ResolverClientNotFoundErrors, 1)
}

func Test_Resolver_Server_Error(t *testing.T) {
	addr, _ := url.Parse("http://localhost:9044")

	metrics := NewTestResolverMetrics()

	// Setup a resolver client with metrics
	rslv := register.NewMeteredRestResolverClient(addr, http.DefaultClient, metrics)

	errCode := http.StatusBadRequest
	errMsg := "Something invalid"
	// Setup a mock resolver
	discoverReply := map[string]interface{}{
		"error": errMsg,
	}
	responder, _ := httpmock.NewJsonResponder(errCode, discoverReply)
	httpmock.RegisterResponder("GET", addr.String()+"/1.0/discover/"+url.QueryEscape(ValidID), responder)

	// Place the call
	_, err := rslv.GetDocument(context.TODO(), ValidID)

	assert.Assert(t, register.IsResolverError(err))
	re := err.(*register.ResolverError)
	assert.Equal(t, re.ErrorType(), register.ServerError)
	assert.ErrorContains(t, re.Err(), errMsg)
	assert.ErrorContains(t, re.Err(), http.StatusText(errCode))

	// Check metrics
	assert.Equal(t, metrics.ResolverClientConnections, 1)
	assert.Equal(t, metrics.ResolverClientConnectionsReleased, 1)
	assert.Equal(t, metrics.ResolverClientServerErrors, 1)
	assert.Equal(t, metrics.ResolverClientNotFoundErrors, 0)
}

func Test_Resolver_Successful_Register(t *testing.T) {
	addr, _ := url.Parse("http://localhost:9031")

	metrics := NewTestResolverMetrics()

	// Setup a resolver client with metrics
	rslv := register.NewMeteredRestResolverClient(addr, http.DefaultClient, metrics)

	// Setup a mock resolver
	registerReply := map[string]interface{}{
		"message": "ok",
	}
	responder, _ := httpmock.NewJsonResponder(200, registerReply)
	httpmock.RegisterResponder("POST", addr.String()+"/1.0/register", responder)

	// Place the call
	document, issuer, keypair := test.HelperGetRegisterDocument()
	err := rslv.RegisterDocument(context.TODO(), document, keypair.PrivateKey, issuer)
	assert.NilError(t, err)

	// Check metrics
	assert.Equal(t, metrics.ResolverClientConnections, 1)
	assert.Equal(t, metrics.ResolverClientConnectionsReleased, 1)
	assert.Equal(t, metrics.ResolverClientNotFoundErrors, 0)
	assert.Equal(t, metrics.ResolverClientServerErrors, 0)
}

func Test_Resolver_Failed_Register(t *testing.T) {
	addr, _ := url.Parse("http://localhost:9031")

	metrics := NewTestResolverMetrics()

	// Setup a resolver client with metrics
	rslv := register.NewMeteredRestResolverClient(addr, http.DefaultClient, metrics)

	errCode := http.StatusInternalServerError
	errMsg := "oh dear"
	// Setup a mock resolver
	registerReply := map[string]interface{}{
		"error": errMsg,
	}
	responder, _ := httpmock.NewJsonResponder(errCode, registerReply)
	httpmock.RegisterResponder("POST", addr.String()+"/1.0/register", responder)

	// Place the call
	document, issuer, keypair := test.HelperGetRegisterDocument()
	err := rslv.RegisterDocument(context.TODO(), document, keypair.PrivateKey, issuer)

	assert.Assert(t, register.IsResolverError(err))
	re := err.(*register.ResolverError)
	assert.Equal(t, re.ErrorType(), register.ServerError)
	assert.ErrorContains(t, re.Err(), errMsg)
	assert.ErrorContains(t, re.Err(), http.StatusText(errCode))

	// Check metrics
	assert.Equal(t, metrics.ResolverClientConnections, 1)
	assert.Equal(t, metrics.ResolverClientConnectionsReleased, 1)
	assert.Equal(t, metrics.ResolverClientServerErrors, 1)
	assert.Equal(t, metrics.ResolverClientNotFoundErrors, 0)
}
