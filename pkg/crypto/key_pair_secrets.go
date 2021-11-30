// Copyright (c) IOTIC LABS LIMITED. All rights reserved. Licensed under the Apache License, Version 2.0.

package crypto

import (
	"crypto/ecdsa"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"

	id "github.com/Iotic-Labs/iotics-identity-go/pkg/identity"
	"github.com/Iotic-Labs/iotics-identity-go/pkg/validation"

	"github.com/tyler-smith/go-bip39"
)

// SeedMethod seed method type
type SeedMethod int

const (
	// SeedMethodBip39 (0) uses pbkdf2 2048 iterations
	SeedMethodBip39 SeedMethod = iota
	// SeedMethodNone (1) is a naive method using hmac_sha256
	SeedMethodNone
)

const (
	// DefaultSeedMethod default seed method
	DefaultSeedMethod = SeedMethodBip39

	minSeedMethodNoneLength = 16
)

// KeyPairSecrets Key pair secrets
type KeyPairSecrets interface {
	Seed() []byte
	Path() string
	SeedMethod() SeedMethod
	Password() string
}

// KeyPair struct
type KeyPair struct {
	PrivateKey      *ecdsa.PrivateKey
	PublicKeyBytes  []byte
	PublicKeyBase58 string
}

type keyPairSecrets struct {
	seed       []byte
	path       string
	seedMethod SeedMethod
	password   string
}

func (s keyPairSecrets) Seed() []byte {
	return s.seed
}
func (s keyPairSecrets) Path() string {
	return s.path
}
func (s keyPairSecrets) Password() string {
	return s.password
}
func (s keyPairSecrets) SeedMethod() SeedMethod {
	return s.seedMethod
}

// NewDefaultKeyPairSecrets builds a valid key pair secrets (default SeedMethodBip39 and default password "")
func NewDefaultKeyPairSecrets(seed []byte, path string) (KeyPairSecrets, error) {
	return NewKeyPairSecrets(seed, path, SeedMethodBip39, "")
}

// NewDefaultKeyPairSecretsWithPassword builds a valid key pair secrets (default SeedMethodBip39)
func NewDefaultKeyPairSecretsWithPassword(seed []byte, path string, password string) (KeyPairSecrets, error) {
	return NewKeyPairSecrets(seed, path, SeedMethodBip39, password)
}

// NewKeyPairSecrets builds a valid key pair secrets
func NewKeyPairSecrets(seed []byte, path string, seedMethod SeedMethod, password string) (KeyPairSecrets, error) {
	// Seed validation
	if seedMethod == SeedMethodNone && len(seed) < minSeedMethodNoneLength {
		return nil, fmt.Errorf("invalid seed length for method 'SeedMethodNone' must be at least %d bytes", minSeedMethodNoneLength)
	}
	if seedMethod == SeedMethodBip39 {
		_, err := SeedBip39ToMnemonic(seed)
		if err != nil {
			return nil, fmt.Errorf("invalid seed for bip39 %s", err)
		}
	}

	// path validation
	if !strings.HasPrefix(path, validation.IoticsPathPrefix) {
		return nil, fmt.Errorf("invalid key pair path '%s' must start with %s", path, validation.IoticsPathPrefix)
	}

	result := &keyPairSecrets{
		seed:       seed,
		path:       path,
		seedMethod: seedMethod,
		password:   password,
	}
	return result, nil
}

// PathForDIDType Build a valid path string given didType and name string
func PathForDIDType(name string, didType id.DidType) string {
	return fmt.Sprintf("%s/%s/%s", validation.IoticsPathPrefix, didType, name)
}

// SeedBip39ToMnemonic takes the seed bytes and returns mnemonic string
func SeedBip39ToMnemonic(seed []byte) (string, error) {
	mnemonic, err := bip39.NewMnemonic(seed)
	if err != nil {
		return "", err
	}
	return mnemonic, nil
}

// ValidateBip39Seed Valid BIP39 seed
func ValidateBip39Seed(seed []byte) error {
	_, err := SeedBip39ToMnemonic(seed)
	return err
}

// MnemonicBip39ToSeed takes mnemonic string and returns seed
func MnemonicBip39ToSeed(mnemonic string) ([]byte, error) {
	seed, err := bip39.EntropyFromMnemonic(mnemonic)
	if err != nil {
		return nil, err
	}
	return seed, nil
}

// GetPrivateKey Get private key from key pair secrets
func GetPrivateKey(secrets KeyPairSecrets) (*ecdsa.PrivateKey, error) {
	var master []byte
	if secrets == nil {
		return nil, fmt.Errorf("invalid key pair secrets")
	}
	if secrets.SeedMethod() == SeedMethodNone {
		h := hmac.New(sha512.New, secrets.Seed())
		_, _ = h.Write([]byte(secrets.Password()))
		master = h.Sum(nil)
	} else if secrets.SeedMethod() == SeedMethodBip39 {
		mnemonic, err := SeedBip39ToMnemonic(secrets.Seed())
		if errors.Is(err, bip39.ErrEntropyLengthInvalid) {
			return nil, fmt.Errorf("invalid seed length (bip39): %s", err)
		}
		if err != nil {
			return nil, fmt.Errorf("master from seed generation failed (bip39): %s", err)
		}
		master = bip39.NewSeed(mnemonic, secrets.Password())
	}

	// Note: It is possible this hashing will produce an invalid exponent
	// valid are in range 0x1 - 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364142
	// See: https://crypto.stackexchange.com/questions/30269/are-all-possible-ec-private-keys-valid#30272
	// We won't implement a workaround here.  If anyone ever reproduces this, please consider sharing you seed + path.
	h := hmac.New(sha256.New, master)
	_, _ = h.Write([]byte(secrets.Path()))
	privateKeyBytes := h.Sum(nil)

	return GetPrivateKeyFromExponent(hex.EncodeToString(privateKeyBytes))
}

// GetPublicKeyBase58FromKeyPairSecrets  Get public key base58 fron key pair secrets
func GetPublicKeyBase58FromKeyPairSecrets(secrets KeyPairSecrets) (string, error) {
	privateKey, err := GetPrivateKey(secrets)
	if err != nil {
		return "", err
	}

	_, publicKeyBase58, err := GetPublicKeysFromPrivateKey(privateKey)
	return publicKeyBase58, err
}

// GetKeyPair Get key pair from key pair secrets
func GetKeyPair(secrets KeyPairSecrets) (*KeyPair, error) {
	privateKey, err := GetPrivateKey(secrets)
	if err != nil {
		return nil, err
	}
	publicKeyDer, publicKeyBase58, err := GetPublicKeysFromPrivateKey(privateKey)
	if err != nil {
		return nil, err
	}
	result := &KeyPair{
		PrivateKey:      privateKey,
		PublicKeyBytes:  publicKeyDer,
		PublicKeyBase58: publicKeyBase58}
	return result, nil
}
