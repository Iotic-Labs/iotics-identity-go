package api_test

import (
	"testing"

	"github.com/Iotic-Labs/iotics-identity-go/pkg/api"
	"github.com/Iotic-Labs/iotics-identity-go/pkg/crypto"
	"github.com/Iotic-Labs/iotics-identity-go/pkg/test"
	"gotest.tools/assert"
)

func TestCreateTwinWithControlDelegation(t *testing.T) {
	resolver := test.NewInMemoryResolver()

	agentID, err := api.CreateAgentIdentity(resolver, &api.CreateIdentityOpts{
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
	twinID, err := api.CreateTwinWithControlDelegation(resolver, opts)
	assert.NilError(t, err)
	assert.Assert(t, twinID.Did() == "did:iotics:iotXqziDRUAqcb7Sd5NcCKMHi2DCvnNKmY7B")
	assert.Assert(t, resolver.CountDiscover.Value() == 2) // override false causes a resolver discover
	assert.Assert(t, resolver.CountRegister.Value() == 2) // create + delegate with 1 register call
}

func TestCreateUserAndAgentWithAuthDelegation(t *testing.T) {
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
	userID, agentID, err := api.CreateUserAndAgentWithAuthDelegation(resolver, opts)
	assert.NilError(t, err)
	assert.Assert(t, userID.Did() == "did:iotics:iotCm3GCjZVF6hc3C9sksLaSWnz3KCmPrCoC")
	assert.Assert(t, agentID.Did() == "did:iotics:iotXHQanTARvNc9WE5NLoDztoZcF3T1Jbx2j")
	assert.Assert(t, resolver.CountDiscover.Value() == 1) // override false causes a resolver discover
	assert.Assert(t, resolver.CountRegister.Value() == 2) // create agent + create user & delegate with 1 call each
}

func TestGetOwnershipOfTwinFromRegisteredIdentity(t *testing.T) {
	resolver := test.NewInMemoryResolver()

	twinID, err := api.CreateTwinIdentity(resolver, &api.CreateIdentityOpts{
		Seed:    test.ValidSeed16B,
		KeyName: "highlevel_twin_0",
		Name:    "#high-twin-0",
		Method:  crypto.SeedMethodBip39,
	})
	assert.NilError(t, err)
	assert.Assert(t, resolver.CountDiscover.Value() == 1) // override false causes a resolver discover
	assert.Assert(t, resolver.CountRegister.Value() == 1) // register 1 twin

	newOwnerID, err := api.CreateTwinIdentity(resolver, &api.CreateIdentityOpts{
		Seed:    test.ValidSeed16B,
		KeyName: "highlevel_twin_0-new",
		Name:    "#high-twin-0-new",
		Method:  crypto.SeedMethodBip39,
	})
	assert.NilError(t, err)
	assert.Assert(t, resolver.CountDiscover.Value() == 2) // override false causes a resolver discover
	assert.Assert(t, resolver.CountRegister.Value() == 2) // register 1 twin

	err = api.GetOwnershipOfTwinFromRegisteredIdentity(resolver, twinID, newOwnerID, "#new-owner")
	assert.NilError(t, err)
	assert.Assert(t, resolver.CountDiscover.Value() == 3) // override false causes a resolver discover
	assert.Assert(t, resolver.CountRegister.Value() == 3) // register 1 twin
}
