// Copyright (c) IOTIC LABS LIMITED. All rights reserved. Licensed under the Apache License, Version 2.0.

package register

import (
	"crypto/ecdsa"
	"errors"
	"fmt"
	"time"

	"github.com/Iotic-Labs/iotics-identity-go/v3/pkg/crypto"
	"github.com/Iotic-Labs/iotics-identity-go/v3/pkg/proof"
	"github.com/golang-jwt/jwt"
)

// AuthenticationClaims Structure for returning decoded authentication tokens
type AuthenticationClaims struct {
	Issuer    *Issuer
	Subject   string
	Audience  string
	IssuedAt  int64
	ExpiresAt int64
}

// challengeClaims structure for building challenge tokens
type challengeClaims struct {
	Proof string `json:"proof"`
	jwt.StandardClaims
}

// ChallengeClaims structure for decoded challenge tokens
type ChallengeClaims struct {
	Signature string
	Issuer    *Issuer
	Audience  string
}

// DidDocumentClaims structure for decoded document tokens
type DidDocumentClaims struct {
	Doc      *RegisterDocument
	Issuer   *Issuer
	Audience string
}

// didDocumentClaims structure for building document tokens
type didDocumentClaims struct {
	Doc *RegisterDocument `json:"doc"`
	jwt.StandardClaims
}

// DefaultAuthTokenStartOffset is the default offset for token valid-from time used. This is to avoid tokens being
// rejected when the client time is marginally ahead of the server (i.e. resolver or Iotics host)
const DefaultAuthTokenStartOffset = 30

func docValidate(doc *RegisterDocument) error {
	errs := doc.Validate()
	if len(errs) != 0 {
		errStr := ""
		for _, e := range errs {
			if len(errStr) != 0 {
				errStr = errStr + ", "
			}
			errStr = fmt.Sprintf("%s%s", errStr, e)
		}
		return fmt.Errorf("document not valid: %s", errStr)
	}
	return nil
}

// DecodeDocumentTokenNoVerify Decode a document token without verifying it
func DecodeDocumentTokenNoVerify(token JwtToken) (*DidDocumentClaims, error) {
	decoded, _, err := new(jwt.Parser).ParseUnverified(string(token), &didDocumentClaims{})
	if err != nil {
		return nil, errors.New("failed to parse token")
	}

	claims, ok := decoded.Claims.(*didDocumentClaims)
	if !ok || claims.Doc == nil {
		return nil, errors.New("failed to parse token")
	}

	err = docValidate(claims.Doc)
	if err != nil {
		return nil, err
	}

	issuer, err := NewIssuerFromString(claims.Issuer)
	if err != nil {
		return nil, err
	}

	result := &DidDocumentClaims{
		Doc:      claims.Doc,
		Issuer:   issuer,
		Audience: claims.Audience,
	}
	return result, nil
}

// DecodeDocumentToken Decode a document token
func DecodeDocumentToken(token JwtToken, publicKeyBase58 string, audience string) (*DidDocumentClaims, error) {
	decoded, err := jwt.ParseWithClaims(string(token), &didDocumentClaims{}, func(token *jwt.Token) (interface{}, error) {
		publicKey, err := crypto.GetPublicKeyFromBase58(publicKeyBase58)
		if err != nil {
			return nil, err
		}
		return publicKey, nil
	})
	if err != nil {
		return nil, err
	}

	claims, ok := decoded.Claims.(*didDocumentClaims)
	if !ok || claims.Doc == nil {
		return nil, errors.New("failed to parse token")
	}

	if len(audience) != 0 && claims.Audience != audience {
		return nil, errors.New("audience does not match")
	}

	err = docValidate(claims.Doc)
	if err != nil {
		return nil, err
	}

	issuer, err := NewIssuerFromString(claims.Issuer)
	if err != nil {
		return nil, err
	}

	result := &DidDocumentClaims{
		Doc:      claims.Doc,
		Issuer:   issuer,
		Audience: claims.Audience,
	}
	return result, nil
}

// JwtToken JWT Token type of string
type JwtToken string

// CreateDocumentToken Create a register document jwt token
func CreateDocumentToken(issuer *Issuer, audience string, doc *RegisterDocument, privateKey *ecdsa.PrivateKey) (JwtToken, error) {
	if privateKey == nil || privateKey.PublicKey.Curve == nil {
		return "", fmt.Errorf("invalid private key")
	}

	claims := didDocumentClaims{
		doc,
		jwt.StandardClaims{
			Issuer:   issuer.String(),
			Audience: audience,
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodES256, claims)
	ss, err := token.SignedString(privateKey)
	return JwtToken(ss), err
}

// DecodeAuthTokenNoVerify Decode a authentication token without verifying it
func DecodeAuthTokenNoVerify(token JwtToken) (*AuthenticationClaims, error) {
	decoded, _, err := new(jwt.Parser).ParseUnverified(string(token), &jwt.StandardClaims{})
	if err != nil {
		return nil, errors.New("failed to parse token")
	}

	claims, ok := decoded.Claims.(*jwt.StandardClaims)
	if !ok {
		return nil, errors.New("failed to parse token")
	}

	issuer, err := NewIssuerFromString(claims.Issuer)
	if err != nil {
		return nil, err
	}
	result := &AuthenticationClaims{
		Issuer:    issuer,
		Subject:   claims.Subject,
		Audience:  claims.Audience,
		IssuedAt:  claims.IssuedAt,
		ExpiresAt: claims.ExpiresAt,
	}
	return result, nil
}

// DecodeAuthToken Decode a authentication token
func DecodeAuthToken(token JwtToken, publicKeyBase58 string, audience string) (*AuthenticationClaims, error) {
	decoded, err := jwt.ParseWithClaims(string(token), &jwt.StandardClaims{}, func(token *jwt.Token) (interface{}, error) {
		publicKey, err := crypto.GetPublicKeyFromBase58(publicKeyBase58)
		if err != nil {
			return nil, err
		}
		return publicKey, nil
	})
	if err != nil {
		return nil, err
	}

	claims, _ := decoded.Claims.(*jwt.StandardClaims)

	if len(audience) != 0 && claims.Audience != audience {
		return nil, errors.New("audience does not match")
	}

	issuer, err := NewIssuerFromString(claims.Issuer)
	if err != nil {
		return nil, err
	}
	result := &AuthenticationClaims{
		Issuer:    issuer,
		Subject:   claims.Subject,
		Audience:  claims.Audience,
		IssuedAt:  claims.IssuedAt,
		ExpiresAt: claims.ExpiresAt,
	}
	return result, nil
}

// CreateAuthToken Create an authentication jwt token
func CreateAuthToken(issuer *Issuer, subject string, audience string, duration time.Duration, privateKey *ecdsa.PrivateKey, startOffset int) (JwtToken, error) {
	if privateKey == nil || privateKey.PublicKey.Curve == nil {
		return "", fmt.Errorf("invalid private key")
	}

	now := time.Now()

	claims := jwt.StandardClaims{
		Issuer:    issuer.String(),
		Subject:   subject,
		Audience:  audience,
		IssuedAt:  now.Unix() - int64(startOffset),
		ExpiresAt: now.Add(duration).Unix(),
	}
	token := jwt.NewWithClaims(jwt.SigningMethodES256, claims)
	ss, err := token.SignedString(privateKey)
	return JwtToken(ss), err
}

// DecodeChallengeTokenNoVerify Decode a challenge token without verifying it
func DecodeChallengeTokenNoVerify(token JwtToken) (*ChallengeClaims, error) {
	decoded, _, err := new(jwt.Parser).ParseUnverified(string(token), &challengeClaims{})
	if err != nil {
		return nil, errors.New("failed to parse token")
	}

	claims, ok := decoded.Claims.(*challengeClaims)
	if !ok {
		return nil, errors.New("failed to parse token")
	}

	issuer, err := NewIssuerFromString(claims.Issuer)
	if err != nil {
		return nil, err
	}
	result := &ChallengeClaims{
		Signature: claims.Proof,
		Issuer:    issuer,
		Audience:  claims.Audience,
	}
	return result, nil
}

// DecodeChallengeToken Decode a challenge token
func DecodeChallengeToken(token JwtToken, publicKeyBase58 string, audience string) (*ChallengeClaims, error) {
	decoded, err := jwt.ParseWithClaims(string(token), &challengeClaims{}, func(token *jwt.Token) (interface{}, error) {
		publicKey, err := crypto.GetPublicKeyFromBase58(publicKeyBase58)
		if err != nil {
			return nil, err
		}
		return publicKey, nil
	})
	if err != nil {
		return nil, err
	}

	claims, _ := decoded.Claims.(*challengeClaims)

	if len(audience) != 0 && claims.Audience != audience {
		return nil, errors.New("audience does not match")
	}

	issuer, err := NewIssuerFromString(claims.Issuer)
	if err != nil {
		return nil, err
	}
	pr := &proof.Proof{
		IssuerDid:  issuer.Did,
		IssuerName: issuer.Name,
		Content:    []byte(claims.Audience),
		Signature:  claims.Proof,
	}

	err = proof.ValidateProof(pr, publicKeyBase58)
	if err != nil {
		return nil, err
	}

	result := &ChallengeClaims{
		Signature: claims.Proof,
		Issuer:    issuer,
		Audience:  claims.Audience,
	}
	return result, nil
}

// CreateChallengeToken returns a new challenge token from the proof.
func CreateChallengeToken(pr *proof.Proof, privateKey *ecdsa.PrivateKey) (JwtToken, error) {
	if privateKey == nil || privateKey.PublicKey.Curve == nil {
		return "", fmt.Errorf("invalid private key")
	}

	issuer, err := NewIssuer(pr.IssuerDid, pr.IssuerName)
	if err != nil {
		return "", err
	}
	claims := challengeClaims{
		pr.Signature,
		jwt.StandardClaims{
			Issuer:   issuer.String(),
			Audience: string(pr.Content[:]),
		},
	}
	token := jwt.NewWithClaims(defaultSigningMethod, claims)
	signed, err := token.SignedString(privateKey)
	return JwtToken(signed), err
}
