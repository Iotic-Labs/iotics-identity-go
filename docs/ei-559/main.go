package main

import (
	"fmt"
	"net/url"
	"time"

	"github.com/Iotic-Labs/iotics-identity-go/pkg/api"
	"github.com/Iotic-Labs/iotics-identity-go/pkg/crypto"
	"github.com/Iotic-Labs/iotics-identity-go/pkg/register"
)

func main() {
	r := "https://did.stg.iotics.com"
	seedBytes, err := api.CreateDefaultSeed()
	if err != nil {
		fmt.Printf("seed err: %v", err)
		return
	}

	opts := &api.CreateIdentityOpts{
		Seed:    seedBytes,
		KeyName: "ak1",
		// Password: nil,
		Name:     "#an1",
		Method:   crypto.SeedMethodBip39,
		Override: true,
	}

	resolverUrl, _ := url.Parse(r)
	resolver := register.NewDefaultRestResolverClient(resolverUrl)
	aid, err := api.CreateAgentIdentity(resolver, opts)
	if err != nil {
		fmt.Printf("agent id err: %v", err)
		return
	}
	opts = &api.CreateIdentityOpts{
		Seed:    seedBytes,
		KeyName: "uk1",
		// Password: nil,
		Name:     "#un1",
		Method:   crypto.SeedMethodBip39,
		Override: true,
	}
	uid, err := api.CreateUserIdentity(resolver, opts)
	if err != nil {
		fmt.Printf("user id err: %v", err)
		return
	}
	err = api.UserDelegatesAuthenticationToAgent(resolver, uid, aid, "#del2")
	if err != nil {
		fmt.Printf("deleg err: %v", err)
		return
	}

	// Keep trying to make Auth' token until allowed
	// Since the creation over agent & user identities populated the cloudfront cache we need to wait for those items to expire (30s?)
	attempts := 0
	for {
		attempts++

		t, err := api.CreateAgentAuthToken(aid, uid.Did(), 1000, "resolver")
		if err != nil {
			fmt.Printf("make token err: %v (attempt %d)\n", err, attempts)
			time.Sleep(time.Second * 10)
		}
		claims, err := register.VerifyAuthentication(resolver, t)
		if err != nil {
			fmt.Printf("verify err: %v (attempt %d)\n", err, attempts)
			time.Sleep(time.Second * 10)
		}

		fmt.Printf("claims: %v\n", claims)
		break
	}
}
