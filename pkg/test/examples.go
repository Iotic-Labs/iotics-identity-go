// Copyright (c) IOTIC LABS LIMITED. All rights reserved. Licensed under the Apache License, Version 2.0.

package test

import (
	"fmt"
	"strings"

	"github.com/Iotic-Labs/iotics-identity-go/v2/pkg/crypto"
	"github.com/Iotic-Labs/iotics-identity-go/v2/pkg/identity"
	"github.com/Iotic-Labs/iotics-identity-go/v2/pkg/proof"
	"github.com/Iotic-Labs/iotics-identity-go/v2/pkg/register"
	"github.com/Iotic-Labs/iotics-identity-go/v2/pkg/validation"
)

const (
	ValidPublicBase58    = "Q9F3CfJDDkfdp5s81tReuhaew12Y56askT1RJCdXcbiHcLvBLz2HHmGPxS6XrrkujxLRCHJ6CkkTKfU3izDgMqLa"
	ValidMnemonicEnglish = "goddess muscle soft human fatal country this hockey great perfect evidence gather industry rack silver small cousin another flee silver casino country sugar purse"
	ValidMnemonicSpanish = "glaciar mojar rueda hueso exponer chupar tanque hijo grano olvido ensayo gaita inmune percha retrato rojo cielo alivio fiel retrato brusco chupar sirena peine"

	ValidBip39Seed = "d2397e8b83cf4a7073a26c1a1cdb6b65"
	ValidPath      = "iotics/0/something/user"
	ValidDid       = "did:iotics:iotHjrmKpPGWyEC4FFo4d6oyzVVk6MXLmEgY"
	OtherDid       = "did:iotics:iotBpJKGEb4xdqZLWoJq3KpWgpbMCSWoZEXr"
	DelegDocDid    = "did:iotics:iotHHHHKpPGWWWC4FFo4d6oyzVVk6MXLmEgY"
	ValidName      = "#aName"
	ValidAudience  = "http://audience/"

	DelegationName      = "#NewDelegAuth"
	OtherDelegationName = "#newDeleg"
	OtherProof          = "MEYCIQDYUBD9JQdM5xe+PTWvIiOTnQtJ5uVPM2SEinDccibmkwIhALQcRa999hkiFg8YRS81GwWiQ/Z0Xrux/PCO/ggpeveI"
)

var (
	ValidSeed16B       = []byte(strings.Repeat("a", 16))
	ValidBip39Seed32B  = []byte(ValidBip39Seed)
	ValidContent       = []byte("a content")
	ValidKeyPairPath   = fmt.Sprintf("%s/plop", validation.IoticsPathPrefix)
	PrivateExponentHex = "263e24ead2c98974a4bdcdb30f99be98ed89463270ee128f80536627fdcdf3ee"

	ValidSecret, _     = crypto.NewDefaultKeyPairSecrets(ValidBip39Seed32B, ValidPath)
	ValidPrivateKey, _ = crypto.GetPrivateKey(ValidSecret)
	ValidKeyPair, _    = crypto.GetKeyPair(ValidSecret)
	ValidSecret2, _    = crypto.NewDefaultKeyPairSecrets(ValidBip39Seed32B, "iotics/0/something/user2")
	ValidKeyPair2, _   = crypto.GetKeyPair(ValidSecret2)
	ValidProof, _      = proof.NewProof(ValidPrivateKey, ValidIssuer.Did, ValidIssuer.Name, ValidContent)
	ValidIssuer, _     = register.NewIssuer(ValidDid, ValidName)
	ValidIssuerKey, _  = register.NewIssuerKey(ValidIssuer.Did, ValidIssuer.Name, ValidKeyPair.PublicKeyBase58)
	PublicKey, _       = register.NewRegisterPublicKey(ValidIssuer.Name, register.PublicKeyType, ValidIssuerKey.PublicKeyBase58, false)

	opts = []register.RegisterDocumentOpts{
		register.AddRootParams(DelegDocDid, identity.Twin, "a proof", false),
		register.AddPublicKeyObj(PublicKey),
	}
	SimpleDoc, _ = register.NewRegisterDocument(opts)

	ValidKeyPairSecretsPlop, _  = crypto.NewKeyPairSecrets([]byte("d2397e8b83cf4a7073a26c1a1cdb6666"), "iotics/0/plop/plop", crypto.SeedMethodBip39, "")
	ValidKeyPairPlop, _         = crypto.GetKeyPair(ValidKeyPairSecretsPlop)
	ValidKeyPairSecretsPlop2, _ = crypto.NewKeyPairSecrets([]byte("d2397e8b83cf4a7073a26c1a1cdb6666"), "iotics/0/plop/plop1", crypto.SeedMethodBip39, "")
	ValidKeyPairPlop2, _        = crypto.GetKeyPair(ValidKeyPairSecretsPlop2)
	ValidKeyPairSecrets3, _     = crypto.NewKeyPairSecrets([]byte("d2397e8b83cf4a7073a26c1a1cdb6683"), "iotics/0/plop/plop3", crypto.SeedMethodBip39, "")
	ValidKeyPair3, _            = crypto.GetKeyPair(ValidKeyPairSecrets3)

	OtherDocDid, _    = identity.MakeIdentifier(ValidKeyPairPlop.PublicKeyBytes)
	OtherDocIssuer, _ = register.NewIssuer(OtherDocDid, "#DelegatedDoc")
)
