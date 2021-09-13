package main

/*
#include <stdlib.h>
*/
import "C"
import (
	"encoding/hex"
	"fmt"
	"github.com/Iotic-Labs/iotics-identity-go/pkg/api"
	"github.com/Iotic-Labs/iotics-identity-go/pkg/crypto"
	"github.com/Iotic-Labs/iotics-identity-go/pkg/identity"
	"github.com/Iotic-Labs/iotics-identity-go/pkg/register"
	"net/url"
	"time"
	"unsafe"
)

//export CreateAgentAuthToken
// Fprint formats using the default formats for its operands and writes to w.
// Spaces are added between operands when neither is a string.
// It returns the number of bytes written and any write error encountered.
func CreateAgentAuthToken(
	agentDid string, agentKeyName string, agentName string, userDid string, seed string, duration int64,
) (*C.char, *C.char) {
	agent, _, err := getAgentIdentity(agentDid, agentKeyName, agentName, seed)
	if err != nil {
		return C.CString(""), C.CString(fmt.Sprintf("FFI lib error: failed to get agent registered identity: %+v", err))
	}
	token, err := api.CreateAgentAuthToken(agent, userDid, time.Duration(duration)*time.Second, "")
	if err != nil {
		return C.CString(""), C.CString(fmt.Sprintf("FFI lib error: failed to get token: %+v", err))
	}
	return C.CString(string(token)), C.CString("")
}

//export CreateTwinDidWithControlDelegation
func CreateTwinDidWithControlDelegation(
	resolverAddress string, agentDid string, agentKeyName string, agentName string, agentSeed string, twinKeyName string, twinName string,
) (*C.char, *C.char) {
	addr, err := url.Parse(resolverAddress)
	if err != nil {
		return C.CString(""), C.CString(fmt.Sprintf("FFI lib error: parsing resolver address failed: %+v", err))
	}
	resolver := register.NewDefaultRestResolverClient(addr)
	agent, seedBytes, err := getAgentIdentity(agentDid, agentKeyName, agentName, agentSeed)
	if err != nil {
		return C.CString(""), C.CString(fmt.Sprintf("FFI lib error: failed to get agent registered identity: %+v", err))
	}
	opts := &api.CreateTwinOpts{
		Seed:           seedBytes,
		AgentId:        agent,
		DelegationName: "#TwinToAgentControlDeleg",
		KeyName:        twinKeyName,
		Name:           twinName,
	}
	twinIdentity, err := api.CreateTwinWithControlDelegation(resolver, opts)
	if err != nil {
		return C.CString(""), C.CString(fmt.Sprintf("FFI lib error: creating twin failed: %+vs", err))
	}
	return C.CString(twinIdentity.Did()), C.CString("")
}

//export FreeUpCString
func FreeUpCString(pointer *C.char) {
	C.free(unsafe.Pointer(pointer))
}

func getAgentIdentity(
	agentDid string, agentKeyName string, agentName string, seed string,
) (register.RegisteredIdentity, []byte, error) {
	seedBytes, err := hex.DecodeString(seed)
	if err != nil {
		return nil, nil, err
	}
	opts := &api.GetIdentityOpts{
		Seed:    seedBytes,
		Did:     agentDid,
		KeyName: agentKeyName,
		Name:    agentName,
		Method:  crypto.SeedMethodBip39,
	}
	agent, err := api.GetAgentIdentity(opts)
	if err != nil {
		return nil, nil, err
	}
	did, err := identity.MakeIdentifier(agent.KeyPair().PublicKeyBytes)
	if err != nil {
		return nil, nil, err
	}
	if did != agentDid {
		opts.Method = crypto.SeedMethodNone
		agent, err = api.GetAgentIdentity(opts)
		if err != nil {
			return nil, nil, err
		}
	}
	return agent, seedBytes, nil
}

func main() {}
