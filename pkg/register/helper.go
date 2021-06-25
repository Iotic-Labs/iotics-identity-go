// Copyright (c) IOTIC LABS LIMITED. All rights reserved. Licensed under the Apache License, Version 2.0.

package register

import (
	"crypto/ecdsa"

	ethcrypto "github.com/ethereum/go-ethereum/crypto"
	"github.com/jbenet/go-base58"
)

// getPublicKeyFromBase58 Get public key ECDSA from public key base58
// NOTE: this is a copy of crypto.GetPublicKeyFromBase58 to avoid circular dependencies
// so it should probably be extracted to another common package
func getPublicKeyFromBase58(publicBase58 string) (*ecdsa.PublicKey, error) {
	publicKeyBytes := base58.DecodeAlphabet(publicBase58, base58.BTCAlphabet)
	return ethcrypto.UnmarshalPubkey(publicKeyBytes)
}
