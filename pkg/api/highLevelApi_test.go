package api_test

import (
	"context"
	"encoding/hex"
	"testing"
	"time"

	"github.com/Iotic-Labs/iotics-identity-go/v3/pkg/advancedapi"
	"github.com/Iotic-Labs/iotics-identity-go/v3/pkg/api"
	"github.com/Iotic-Labs/iotics-identity-go/v3/pkg/crypto"
	"github.com/Iotic-Labs/iotics-identity-go/v3/pkg/identity"
	"github.com/Iotic-Labs/iotics-identity-go/v3/pkg/register"
	"github.com/Iotic-Labs/iotics-identity-go/v3/pkg/test"
	"gotest.tools/assert"
)

func TestCreateTwinWithControlDelegation(t *testing.T) {
	ctx := context.TODO()
	resolver := test.NewInMemoryResolver()

	agentID, err := api.CreateAgentIdentity(ctx, resolver, &api.CreateIdentityOpts{
		Seed:    test.ValidSeed16B,
		KeyName: "highlevel_agent_0",
		Name:    "#high-agent-0",
		Method:  crypto.SeedMethodBip39,
	})
	assert.NilError(t, err)
	assert.Assert(t, resolver.CountDiscover.Value() == 1) // override false causes a resolver discover
	assert.Assert(t, resolver.CountRegister.Value() == 1) // register 1 agent

	opts := &api.CreateTwinOpts{
		Seed:           test.ValidSeed16B,
		KeyName:        "highlevel_twin_0",
		Name:           "#high-twin-0",
		AgentID:        agentID,
		DelegationName: "#Delegation",
	}
	twinID, err := api.CreateTwinWithControlDelegation(ctx, resolver, opts)
	assert.NilError(t, err)
	assert.Assert(t, twinID.Did() == "did:iotics:iotXqziDRUAqcb7Sd5NcCKMHi2DCvnNKmY7B")
	assert.Assert(t, resolver.CountDiscover.Value() == 2) // override false causes a resolver discover
	assert.Assert(t, resolver.CountRegister.Value() == 2) // create + delegate with 1 register call

	doc, err := resolver.GetDocument(ctx, twinID.Did())
	assert.NilError(t, err)
	assert.Check(t, len(doc.DelegateControl) == 1)
	assert.Check(t, doc.DelegateControl[0].ID == opts.DelegationName)
	assert.Check(t, doc.DelegateControl[0].Controller == agentID.Issuer().String())
}

func TestCreateUserAndAgentWithAuthDelegation(t *testing.T) {
	ctx := context.TODO()

	resolver := test.NewInMemoryResolver()
	opts := &api.CreateUserAndAgentWithAuthDelegationOpts{
		UserSeed:       test.ValidSeed16B,
		UserKeyName:    "highlevel_user_0",
		UserName:       "#high-user-0",
		AgentSeed:      test.ValidSeed16B,
		AgentKeyName:   "highlevel_agent_0",
		AgentName:      "#high-agent-0",
		DelegationName: "#Delegation",
	}
	userID, agentID, err := api.CreateUserAndAgentWithAuthDelegation(ctx, resolver, opts)
	assert.NilError(t, err)
	assert.Assert(t, userID.Did() == "did:iotics:iotCm3GCjZVF6hc3C9sksLaSWnz3KCmPrCoC")
	assert.Assert(t, agentID.Did() == "did:iotics:iotXHQanTARvNc9WE5NLoDztoZcF3T1Jbx2j")
	assert.Assert(t, resolver.CountDiscover.Value() == 1) // override false causes a resolver discover
	assert.Assert(t, resolver.CountRegister.Value() == 2) // create agent + create user & delegate with 1 call each

	doc, err := resolver.GetDocument(ctx, userID.Did())
	assert.NilError(t, err)
	assert.Check(t, len(doc.DelegateAuthentication) == 1)
	assert.Check(t, doc.DelegateAuthentication[0].ID == opts.DelegationName)
	assert.Check(t, doc.DelegateAuthentication[0].Controller == agentID.Issuer().String())
}

func TestCreateAgentAuthToken(t *testing.T) {
	ctx := context.TODO()

	resolver := test.NewInMemoryResolver()
	opts := &api.CreateUserAndAgentWithAuthDelegationOpts{
		UserSeed:       test.ValidSeed16B,
		UserKeyName:    "highlevel_user_0",
		UserName:       "#high-user-0",
		AgentSeed:      test.ValidSeed16B,
		AgentKeyName:   "highlevel_agent_0",
		AgentName:      "#high-agent-0",
		DelegationName: "#Delegation",
	}
	userID, agentID, err := api.CreateUserAndAgentWithAuthDelegation(ctx, resolver, opts)
	assert.NilError(t, err)
	assert.Assert(t, userID.Did() == "did:iotics:iotCm3GCjZVF6hc3C9sksLaSWnz3KCmPrCoC")
	assert.Assert(t, agentID.Did() == "did:iotics:iotXHQanTARvNc9WE5NLoDztoZcF3T1Jbx2j")
	assert.Assert(t, resolver.CountDiscover.Value() == 1) // override false causes a resolver discover
	assert.Assert(t, resolver.CountRegister.Value() == 2) // create agent + create user & delegate with 1 call each

	authToken, err := api.CreateAgentAuthToken(agentID, userID.Did(), time.Minute, "audience")
	assert.NilError(t, err)

	authClaims, err := register.VerifyAuthentication(ctx, resolver, authToken)
	assert.NilError(t, err)
	assert.DeepEqual(t, authClaims.Issuer, agentID.Issuer())
}

func TestCreateDefaultSeed(t *testing.T) {
	seed1, err := api.CreateDefaultSeed()
	assert.NilError(t, err)

	seed2, err := api.CreateDefaultSeed()
	assert.NilError(t, err)

	assert.Check(t, hex.EncodeToString(seed1) != hex.EncodeToString(seed2))
}

func TestGetOwnershipOfTwinFromRegisteredIdentity(t *testing.T) {
	ctx := context.TODO()

	resolver := test.NewInMemoryResolver()

	twinID, err := api.CreateTwinIdentity(ctx, resolver, &api.CreateIdentityOpts{
		Seed:    test.ValidSeed16B,
		KeyName: "highlevel_twin_0",
		Name:    "#high-twin-0",
		Method:  crypto.SeedMethodBip39,
	})
	assert.NilError(t, err)
	assert.Assert(t, resolver.CountDiscover.Value() == 1) // override false causes a resolver discover
	assert.Assert(t, resolver.CountRegister.Value() == 1) // register 1 twin

	newOwnerID, err := api.CreateTwinIdentity(ctx, resolver, &api.CreateIdentityOpts{
		Seed:    test.ValidSeed16B,
		KeyName: "highlevel_twin_0-new",
		Name:    "#high-twin-0-new",
		Method:  crypto.SeedMethodBip39,
	})
	assert.NilError(t, err)
	assert.Assert(t, resolver.CountDiscover.Value() == 2) // override false causes a resolver discover
	assert.Assert(t, resolver.CountRegister.Value() == 2) // register 1 twin

	err = api.GetOwnershipOfTwinFromRegisteredIdentity(ctx, resolver, twinID, newOwnerID, "#new-owner")
	assert.NilError(t, err)
	assert.Assert(t, resolver.CountDiscover.Value() == 3) // override false causes a resolver discover
	assert.Assert(t, resolver.CountRegister.Value() == 3) // register 1 twin

	doc, err := resolver.GetDocument(ctx, twinID.Did())
	assert.NilError(t, err)
	assert.Check(t, len(doc.PublicKeys) == 2)

	_, err = advancedapi.GetIssuerByPublicKey(doc, newOwnerID.KeyPair().PublicKeyBase58)
	assert.NilError(t, err)
}

func TestDelegateControl(t *testing.T) {
	ctx := context.TODO()

	resolver := test.NewInMemoryResolver()

	agentID, err := api.CreateAgentIdentity(ctx, resolver, &api.CreateIdentityOpts{
		Seed:    test.ValidSeed16B,
		KeyName: "highlevel_agent_0",
		Name:    "#high-agent-0",
		Method:  crypto.SeedMethodBip39,
	})
	assert.NilError(t, err)
	assert.Assert(t, resolver.CountDiscover.Value() == 1) // override false causes a resolver discover
	assert.Assert(t, resolver.CountRegister.Value() == 1) // register 1 agent

	twinID, err := api.CreateTwinIdentity(ctx, resolver, &api.CreateIdentityOpts{
		Seed:    test.ValidSeed16B,
		KeyName: "highlevel_twin_0",
		Name:    "#high-twin-0",
		Method:  crypto.SeedMethodBip39,
	})
	assert.NilError(t, err)
	assert.Assert(t, resolver.CountDiscover.Value() == 2) // override false causes a resolver discover
	assert.Assert(t, resolver.CountRegister.Value() == 2) // register 1 twin

	err = api.DelegateControl(ctx, resolver, twinID, agentID, "#delegation")
	assert.NilError(t, err)
	assert.Assert(t, resolver.CountDiscover.Value() == 4) // two discovers
	assert.Assert(t, resolver.CountRegister.Value() == 3) // register 1 twin
}

// setupTwinAndAgent
func setupTwinAndAgent(t *testing.T, resolver register.ResolverClient) (string, register.RegisteredIdentity, register.RegisteredIdentity) {
	ctx := context.TODO()

	privateKeyExponent := "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"

	keyPair, err := advancedapi.GetKeyPairFromPrivateExponentHex(privateKeyExponent)
	assert.NilError(t, err)

	twinIdentity, _, err := advancedapi.CreateNewIdentityAndRegister(ctx, resolver, identity.Twin, keyPair, "#twin", false)
	assert.NilError(t, err)

	agentIdentity, err := api.CreateTwinIdentity(ctx, resolver, &api.CreateIdentityOpts{
		Seed:    test.ValidSeed16B,
		KeyName: "highlevel_twin_0-new",
		Name:    "#high-twin-0-new",
		Method:  crypto.SeedMethodBip39,
	})
	assert.NilError(t, err)

	return privateKeyExponent, twinIdentity, agentIdentity
}

func TestSetupResolverCalls(t *testing.T) {
	resolver := test.NewInMemoryResolver()
	_, _, _ = setupTwinAndAgent(t, resolver)

	assert.Assert(t, resolver.CountDiscover.Value() == 2) // Two discovers (override false for agent & twin)
	assert.Assert(t, resolver.CountRegister.Value() == 2) // Two registers (agent & twin)
}

func TestTakeOwnershipOfTwinFromPrivateExponentHex(t *testing.T) {
	ctx := context.TODO()

	resolver := test.NewInMemoryResolver()
	privateKeyExponent, twinIdentity, agentIdentity := setupTwinAndAgent(t, resolver)

	err := api.TakeOwnershipOfTwinByPrivateExponentHex(ctx, resolver, twinIdentity.Issuer(), privateKeyExponent, agentIdentity, "#new-owner")
	assert.NilError(t, err)
	assert.Assert(t, resolver.CountDiscover.Value() == 3) // override false causes a resolver discover
	assert.Assert(t, resolver.CountRegister.Value() == 3) // register 1 twin update

	doc, err := resolver.GetDocument(ctx, twinIdentity.Did())
	assert.NilError(t, err)
	assert.Check(t, len(doc.PublicKeys) == 2)

	_, err = advancedapi.GetIssuerByPublicKey(doc, agentIdentity.KeyPair().PublicKeyBase58)
	assert.NilError(t, err)
}

func TestDelegateControlByPrivateExponentHex(t *testing.T) {
	ctx := context.TODO()

	resolver := test.NewInMemoryResolver()
	privateKeyExponent, twinIdentity, agentIdentity := setupTwinAndAgent(t, resolver)

	err := api.DelegateControlByPrivateExponentHex(ctx, resolver, twinIdentity.Issuer(), privateKeyExponent, agentIdentity, "#delegation")
	assert.NilError(t, err)
	assert.Assert(t, resolver.CountDiscover.Value() == 4) // override false causes a resolver discover
	assert.Assert(t, resolver.CountRegister.Value() == 3) // register 1 twin update

	doc, err := resolver.GetDocument(ctx, twinIdentity.Did())
	assert.NilError(t, err)
	assert.Check(t, len(doc.DelegateControl) == 1)
}

func TestTakeOwnershipOfTwinAndDelegateControlByPrivateExponentHex(t *testing.T) {
	ctx := context.TODO()

	resolver := test.NewInMemoryResolver()
	privateKeyExponent, twinIdentity, agentIdentity := setupTwinAndAgent(t, resolver)

	err := api.TakeOwnershipOfTwinAndDelegateControlByPrivateExponentHex(ctx, resolver, twinIdentity.Issuer(), privateKeyExponent, agentIdentity, "#new-owner", "#new-delegation")
	assert.NilError(t, err)
	assert.Assert(t, resolver.CountDiscover.Value() == 3) // override false causes a resolver discover
	assert.Assert(t, resolver.CountRegister.Value() == 3) // register 1 twin update

	doc, err := resolver.GetDocument(ctx, twinIdentity.Did())
	assert.NilError(t, err)
	assert.Check(t, len(doc.PublicKeys) == 2)
	assert.Check(t, len(doc.DelegateControl) == 1)

	_, err = advancedapi.GetIssuerByPublicKey(doc, agentIdentity.KeyPair().PublicKeyBase58)
	assert.NilError(t, err)
}
