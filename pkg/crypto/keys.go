// Copyright (c) IOTIC LABS LIMITED. All rights reserved. Licensed under the Apache License, Version 2.0.

package crypto

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"

	"github.com/fomichev/secp256k1"
	"github.com/jbenet/go-base58"
)

// GetPrivateKeyFromExponent Get private key (ECDSA) from private exponent as hex string
func GetPrivateKeyFromExponent(privateExponentHex string) (*ecdsa.PrivateKey, error) {
	privateKeyBytes, err := hex.DecodeString(privateExponentHex)
	if err != nil {
		return nil, err
	}

	privateECDSA := new(ecdsa.PrivateKey)
	privateECDSA.PublicKey.Curve = secp256k1.SECP256K1()
	privateECDSA.D = new(big.Int).SetBytes(privateKeyBytes)

	// The privateECDSA.D must < N
	if privateECDSA.D.Cmp(privateECDSA.Curve.Params().N) >= 0 {
		return nil, fmt.Errorf("invalid private key, >=N")
	}
	// The privateECDSA.D must not be zero or negative.
	if privateECDSA.D.Sign() <= 0 {
		return nil, fmt.Errorf("invalid length, need 256 bits")
	}

	privateECDSA.PublicKey.X, privateECDSA.PublicKey.Y = privateECDSA.PublicKey.Curve.ScalarBaseMult(privateKeyBytes)
	if privateECDSA.PublicKey.X == nil {
		return nil, errors.New("invalid private key")
	}
	return privateECDSA, nil
}

// GetPublicKeysFromPrivateKey Get public keys (bytes and base58) from private key (ECDSA)
func GetPublicKeysFromPrivateKey(privateKey *ecdsa.PrivateKey) ([]byte, string, error) {
	publicKey := privateKey.Public()
	publicKeyECDSA, ok := publicKey.(*ecdsa.PublicKey)
	if !ok {
		return nil, "", errors.New("error casting public key to ECDSA")
	}

	publicKeyDer := elliptic.Marshal(secp256k1.SECP256K1(), publicKeyECDSA.X, publicKeyECDSA.Y)
	publicKeyBase58 := base58.EncodeAlphabet(publicKeyDer, base58.BTCAlphabet)

	return publicKeyDer, publicKeyBase58, nil
}

// GetPublicKeyFromBase58 Get public key ECDSA from public key base58
func GetPublicKeyFromBase58(publicBase58 string) (*ecdsa.PublicKey, error) {
	publicKeyBytes := base58.DecodeAlphabet(publicBase58, base58.BTCAlphabet)

	curve := secp256k1.SECP256K1()
	x, y := elliptic.Unmarshal(curve, publicKeyBytes)
	if x == nil {
		return nil, fmt.Errorf("invalid secp256k1 public key")
	}
	return &ecdsa.PublicKey{Curve: curve, X: x, Y: y}, nil
}
