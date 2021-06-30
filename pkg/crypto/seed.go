package crypto

import (
	"fmt"
	"github.com/tyler-smith/go-bip39"
)

// CreateSeed Create a new seed (secrets).
func CreateSeed(length int) ([]byte, error) {
	if length != 128 && length != 256 {
		return nil, fmt.Errorf("length must be 128 or 256")
	}
	entropy, err := bip39.NewEntropy(length)
	if err != nil {
		return nil, err
	}
	return entropy, nil
}
