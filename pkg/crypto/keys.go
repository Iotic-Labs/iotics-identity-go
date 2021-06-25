// Copyright (c) IOTIC LABS LIMITED. All rights reserved. Licensed under the Apache License, Version 2.0.

package crypto

import (
	"crypto/ecdsa"
	"encoding/hex"
	"errors"

	ethcrypto "github.com/ethereum/go-ethereum/crypto"
	"github.com/jbenet/go-base58"
)

// GetPrivateKeyFromExponent Get private key (ECDSA) from private exponent as hex string
func GetPrivateKeyFromExponent(privateExponentHex string) (*ecdsa.PrivateKey, error) {
	privateKeyBytes, err := hex.DecodeString(privateExponentHex)
	if err != nil {
		return nil, err
	}
	return ethcrypto.ToECDSA(privateKeyBytes)
}

// GetPublicKeysFromPrivateKey Get public keys (bytes and base58) from private key (ECDSA)
func GetPublicKeysFromPrivateKey(privateKey *ecdsa.PrivateKey) ([]byte, string, error) {
	publicKey := privateKey.Public()
	publicKeyECDSA, ok := publicKey.(*ecdsa.PublicKey)
	if !ok {
		return nil, "", errors.New("error casting public key to ECDSA")
	}

	publicKeyDer := ethcrypto.FromECDSAPub(publicKeyECDSA)
	publicKeyBase58 := base58.EncodeAlphabet(publicKeyDer, base58.BTCAlphabet)

	return publicKeyDer, publicKeyBase58, nil
}

// GetPublicKeyFromBase58 Get public key ECDSA from public key base58
func GetPublicKeyFromBase58(publicBase58 string) (*ecdsa.PublicKey, error) {
	publicKeyBytes := base58.DecodeAlphabet(publicBase58, base58.BTCAlphabet)
	return ethcrypto.UnmarshalPubkey(publicKeyBytes)
}
