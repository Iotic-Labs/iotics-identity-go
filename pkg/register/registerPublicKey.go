// Copyright (c) IOTIC LABS LIMITED. All rights reserved. Licensed under the Apache License, Version 2.0.

package register

import "github.com/Iotic-Labs/iotics-identity-go/v2/pkg/validation"

// NOTE: the RegisterPublicKey type is defined in document.go so that the struct definitions are in one place
// NOTE: also note that Revoked property would conflict with the RegisterKey interface Revoked() func
// so the interface method is called IsRevoked()

// NewRegisterPublicKey returns a new register public key from the current setting revoke field.
func NewRegisterPublicKey(name string, keyType KeyType, publicKeyBase58 string, revoked bool) (*RegisterPublicKey, error) {
	// NOTE: Python method was called build
	if err := validation.ValidateKeyName(name); err != nil {
		return nil, err
	}
	result := &RegisterPublicKey{
		ID:              name,
		Type:            keyType.String(),
		PublicKeyBase58: publicKeyBase58,
		Revoked:         revoked,
	}
	return result, nil
}

// NewRegisterPublicKeyFromMap returns a new register public key from map
func NewRegisterPublicKeyFromMap(data map[string]interface{}) (*RegisterPublicKey, error) {
	// NOTE: Python method was called from_dict
	name := data["id"].(string)
	keyType := data["keyType"].(KeyType)
	publicKeyBase58 := data["publicKeyBase58"].(string)
	revoked := data["revoked"].(bool)
	return NewRegisterPublicKey(name, keyType, publicKeyBase58, revoked)
}

// Base58 get public key base58
func (r RegisterPublicKey) Base58() string {
	return r.PublicKeyBase58
}

// IsRevoked get revoked bool
func (r RegisterPublicKey) IsRevoked() bool {
	return bool(r.Revoked)
}

// Clone clone a RegisterPublicKey and return a new one
func (r RegisterPublicKey) Clone() (*RegisterPublicKey, error) {
	// NOTE: Python method was called get_new_key
	// NOTE: ignore error, because we're cloning a valid object
	keyType, _ := NewKeyType(r.Type)
	return NewRegisterPublicKey(r.ID, keyType, r.PublicKeyBase58, r.Revoked)
}

// Equal compare RegisterPublicKey instances
func (r RegisterPublicKey) Equal(other RegisterPublicKey) bool {
	return r.ID == other.ID &&
		r.Type == other.Type &&
		r.PublicKeyBase58 == other.PublicKeyBase58 &&
		r.Revoked == other.Revoked
}

// ToMap get a map
func (r RegisterPublicKey) ToMap() map[string]interface{} {
	// NOTE: Python method was called to_dict
	result := make(map[string]interface{})
	result["id"] = r.ID
	result["type"] = r.Type
	result["publicKeyBase58"] = r.PublicKeyBase58
	result["revoked"] = r.Revoked
	return result
}

func convertRegisterPublicKeyMapToSlice(keys map[string]*RegisterPublicKey) []RegisterPublicKey {
	authKeys := make([]RegisterPublicKey, 0, len(keys))
	for _, v := range keys {
		authKeys = append(authKeys, *v)
	}
	return authKeys
}

func convertReturnPublicKeySliceToMap(slice []RegisterPublicKey) map[string]*RegisterPublicKey {
	result := map[string]*RegisterPublicKey{}
	for _, v := range slice {
		result[v.ID] = &RegisterPublicKey{
			ID:              v.ID,
			Type:            v.Type,
			PublicKeyBase58: v.PublicKeyBase58,
			Revoked:         v.Revoked,
		}
	}
	return result
}

func convertReturnDelegationSliceToMap(slice []RegisterDelegationProof) map[string]*RegisterDelegationProof {
	result := map[string]*RegisterDelegationProof{}
	for _, v := range slice {
		result[v.ID] = &RegisterDelegationProof{
			ID:         v.ID,
			Controller: v.Controller,
			Proof:      v.Proof,
			ProofType:  v.ProofType,
			Revoked:    v.Revoked,
		}
	}
	return result
}
