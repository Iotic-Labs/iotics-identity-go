// Copyright (c) IOTIC LABS LIMITED. All rights reserved. Licensed under the Apache License, Version 2.0.

package register_test

import (
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/Iotic-Labs/iotics-identity-go/pkg/test"

	"github.com/jarcoal/httpmock"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"gotest.tools/assert"

	"github.com/Iotic-Labs/iotics-identity-go/pkg/register"
)

var (
	// 'agent1'
	ValidID    = "did:iotics:iotYJuJs2V31BHc5HvVRM3Aa5T2BD5Q9v3Rq"
	ValidToken = "eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NiJ9.eyJpc3MiOiJkaWQ6aW90aWNzOmlvdFlKdUpzMlYzMUJIYzVIdlZSTTNBYTVUMkJENVE5djNScSNhZ2VudC0wIiwiYXVkIjoibW9jazovL3Jlc29sdmVyIiwiZG9jIjp7IkBjb250ZXh0IjoiaHR0cHM6Ly93M2lkLm9yZy9kaWQvdjEiLCJpZCI6ImRpZDppb3RpY3M6aW90WUp1SnMyVjMxQkhjNUh2VlJNM0FhNVQyQkQ1UTl2M1JxIiwiaW90aWNzU3BlY1ZlcnNpb24iOiIwLjAuMSIsImlvdGljc0RJRFR5cGUiOiJhZ2VudCIsInVwZGF0ZVRpbWUiOjE2MDI0OTgyOTc5MjcsInByb29mIjoiTUVVQ0lRQ0xFNWZVdWlTVXZvbklEaEUzT1ZIcXY2cVNuK1UxdFY4RFNleHpaMHl4M1FJZ2FyV3pONzFsaTlLU3VBOHhMUWg3NmpkSkJHN1QyRUEwMjJMbnFnR1hxUDA9IiwicHVibGljS2V5IjpbeyJpZCI6IiNhZ2VudC0wIiwidHlwZSI6IlNlY3AyNTZrMVZlcmlmaWNhdGlvbktleTIwMTgiLCJwdWJsaWNLZXlCYXNlNTgiOiJSR2p6TDU4Zmd4dlZxR1Iyam5YRWZCZlMzV3g0ZHZNQnR4NzRRWXBObUN4dHdGeDJtNTZxSlBkeU5Xa1Z3dVBSOGs2WlB2dTI5N1Z6aTlDWVNQdTdpMmdoIiwicmV2b2tlZCI6ZmFsc2V9XSwiYXV0aGVudGljYXRpb24iOltdLCJkZWxlZ2F0ZUNvbnRyb2wiOltdLCJkZWxlZ2F0ZUF1dGhlbnRpY2F0aW9uIjpbXSwibWV0YWRhdGEiOnt9fX0.CHl_30AhfFe-Cfny8axwdmZ_iF4nhFFxUsm0rcMJIQGCrN3X-HcSX60X7x2IDVM4Sbw-JGbgpgZ6QRJJyhxYTA"
)

func init() {
	httpmock.Activate()
}

func checkMetrics(t *testing.T, reg *prometheus.Registry, expected string) {
	names := []string{
		register.MetricResolverErrors,
	}

	// Prefix names with namespace and subsystem
	for i, n := range names {
		names[i] = fmt.Sprintf("%s_%s_%s", register.MetricNamespace, register.MetricSubsystem, n)
	}

	err := testutil.GatherAndCompare(reg, strings.NewReader(expected), names...)
	assert.NilError(t, err)
}

func Test_Resolver_Successful_Get(t *testing.T) {
	register.ResetMetrics()
	reg := prometheus.NewRegistry()
	register.RegisterMetrics(reg)

	addr, _ := url.Parse("http://localhost:9034")

	// Setup a resolver client
	// Note: Passing in http.DefaultClient since by default, e.g. via NewDefaultRestResolverClient, a new http.Client
	// instance is used. httpmock however expects to work against the default client, unless using
	// httpmock.ActivateNonDefault().
	rslv := register.NewRestResolverClientWithCustomClient(addr, http.DefaultClient)

	// Setup a mock resolver
	discoverReply := map[string]interface{}{
		"token": ValidToken,
	}
	responder, _ := httpmock.NewJsonResponder(200, discoverReply)
	httpmock.RegisterResponder("GET", addr.String()+"/1.0/discover/"+url.QueryEscape(ValidID), responder)

	// Place the call
	_, err := rslv.GetDocument(ValidID)
	assert.NilError(t, err)

	expected := ""
	checkMetrics(t, reg, expected)
}

func Test_Resolver_Notfound_Error(t *testing.T) {
	register.ResetMetrics()
	reg := prometheus.NewRegistry()
	register.RegisterMetrics(reg)

	addr, _ := url.Parse("http://localhost:9044")

	// Setup a resolver client
	rslv := register.NewRestResolverClientWithCustomClient(addr, http.DefaultClient)

	// Setup a mock resolver
	discoverReply := map[string]interface{}{
		"error": "Notfound",
	}
	responder, _ := httpmock.NewJsonResponder(http.StatusNotFound, discoverReply)
	httpmock.RegisterResponder("GET", addr.String()+"/1.0/discover/"+url.QueryEscape(ValidID), responder)

	// Place the call
	_, err := rslv.GetDocument(ValidID)

	assert.Assert(t, register.IsResolverError(err))
	re := err.(*register.ResolverError)
	assert.Equal(t, re.ErrorType(), register.NotFound)

	expected := `# HELP iotics_identity_resolver_errors_total Total resolver client errors by error type
	# TYPE iotics_identity_resolver_errors_total counter
	iotics_identity_resolver_errors_total{type="notfound"} 1
`
	checkMetrics(t, reg, expected)
}

func Test_Resolver_Server_Error(t *testing.T) {
	register.ResetMetrics()
	reg := prometheus.NewRegistry()
	register.RegisterMetrics(reg)

	addr, _ := url.Parse("http://localhost:9044")

	// Setup a resolver client
	rslv := register.NewRestResolverClientWithCustomClient(addr, http.DefaultClient)

	errCode := http.StatusBadRequest
	errMsg := "Something invalid"
	// Setup a mock resolver
	discoverReply := map[string]interface{}{
		"error": errMsg,
	}
	responder, _ := httpmock.NewJsonResponder(errCode, discoverReply)
	httpmock.RegisterResponder("GET", addr.String()+"/1.0/discover/"+url.QueryEscape(ValidID), responder)

	// Place the call
	_, err := rslv.GetDocument(ValidID)

	assert.Assert(t, register.IsResolverError(err))
	re := err.(*register.ResolverError)
	assert.Equal(t, re.ErrorType(), register.ServerError)
	assert.ErrorContains(t, re.Err(), errMsg)
	assert.ErrorContains(t, re.Err(), http.StatusText(errCode))

	expected := `# HELP iotics_identity_resolver_errors_total Total resolver client errors by error type
	# TYPE iotics_identity_resolver_errors_total counter
	iotics_identity_resolver_errors_total{type="server"} 1
`
	checkMetrics(t, reg, expected)
}

func Test_Resolver_Successful_Register(t *testing.T) {
	register.ResetMetrics()
	reg := prometheus.NewRegistry()
	register.RegisterMetrics(reg)

	addr, _ := url.Parse("http://localhost:9031")

	// Setup a resolver client
	rslv := register.NewRestResolverClientWithCustomClient(addr, http.DefaultClient)

	// Setup a mock resolver
	registerReply := map[string]interface{}{
		"message": "ok",
	}
	responder, _ := httpmock.NewJsonResponder(200, registerReply)
	httpmock.RegisterResponder("POST", addr.String()+"/1.0/register", responder)

	// Place the call
	document, issuer, keypair := test.HelperGetRegisterDocument()
	err := rslv.RegisterDocument(document, keypair.PrivateKey, issuer)
	assert.NilError(t, err)

	expected := ""
	checkMetrics(t, reg, expected)
}

func Test_Resolver_Failed_Register(t *testing.T) {
	register.ResetMetrics()
	reg := prometheus.NewRegistry()
	register.RegisterMetrics(reg)

	addr, _ := url.Parse("http://localhost:9031")

	// Setup a resolver client
	rslv := register.NewRestResolverClientWithCustomClient(addr, http.DefaultClient)

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
	err := rslv.RegisterDocument(document, keypair.PrivateKey, issuer)

	assert.Assert(t, register.IsResolverError(err))
	re := err.(*register.ResolverError)
	assert.Equal(t, re.ErrorType(), register.ServerError)
	assert.ErrorContains(t, re.Err(), errMsg)
	assert.ErrorContains(t, re.Err(), http.StatusText(errCode))

	expected := `# HELP iotics_identity_resolver_errors_total Total resolver client errors by error type
	# TYPE iotics_identity_resolver_errors_total counter
	iotics_identity_resolver_errors_total{type="server"} 1
`
	checkMetrics(t, reg, expected)
}
