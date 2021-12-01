package main

// #include <stdio.h>
// #include <errno.h>
// #include <stdlib.h>
import "C"
import (
	"encoding/hex"
	"fmt"
	"net/url"
	"time"
	"unsafe"

	"github.com/Iotic-Labs/iotics-identity-go/pkg/api"
	"github.com/Iotic-Labs/iotics-identity-go/pkg/crypto"
	"github.com/Iotic-Labs/iotics-identity-go/pkg/identity"
	"github.com/Iotic-Labs/iotics-identity-go/pkg/register"
)

type GetIDFunc = func(opts *api.GetIdentityOpts) (register.RegisteredIdentity, error)

//export CreateDefaultSeed
func CreateDefaultSeed() (*C.char, *C.char) {
	res, err := api.CreateDefaultSeed()
	if err != nil {
		return C.CString(""), C.CString(fmt.Sprintf("FFI lib error: failed to create default length seed: %+v", err))
	}
	return C.CString(hex.EncodeToString(res)), nil
}

//export MnemonicBip39ToSeed
func MnemonicBip39ToSeed(cMnemonic *C.char) (*C.char, *C.char) {
	mnemonic := C.GoString(cMnemonic)
	res, err := crypto.MnemonicBip39ToSeed(mnemonic)
	if err != nil {
		return C.CString(""), C.CString(fmt.Sprintf("FFI lib error: failed to create default length seed: %+v", err))
	}
	return C.CString(hex.EncodeToString(res)), nil
}

//export SeedBip39ToMnemonic
func SeedBip39ToMnemonic(cSeed *C.char) (*C.char, *C.char) {
	seedBytes, err := hex.DecodeString(C.GoString(cSeed))
	if err != nil {
		return C.CString(""), C.CString(fmt.Sprintf("FFI lib error: failed to decode seed: %+v", err))
	}
	res, err := crypto.SeedBip39ToMnemonic(seedBytes)
	if err != nil {
		return nil, C.CString(fmt.Sprintf("FFI lib error: failed to create default length seed: %+v", err))
	}
	return C.CString(res), nil
}

//export CreateAgentIdentity
func CreateAgentIdentity(cResolverAddress *C.char, cKeyName *C.char, cName *C.char, cSeed *C.char,
) (*C.char, *C.char) {
	return createIdentity(false, cResolverAddress, cKeyName, cName, cSeed)
}

//export CreateUserIdentity
func CreateUserIdentity(cResolverAddress *C.char, cKeyName *C.char, cName *C.char, cSeed *C.char,
) (*C.char, *C.char) {
	return createIdentity(true, cResolverAddress, cKeyName, cName, cSeed)
}

//export UserDelegatesAuthenticationToAgent
func UserDelegatesAuthenticationToAgent(
	cResolverAddress *C.char,

	cAgentDid *C.char,
	cAgentKeyName *C.char,
	cAgentName *C.char,
	cAgentSeed *C.char,

	cUserDid *C.char,
	cUserKeyName *C.char,
	cUserName *C.char,
	cUserSeed *C.char,

	cDelegationName *C.char) *C.char {

	resolverAddress := C.GoString(cResolverAddress)
	delegationName := C.GoString(cDelegationName)

	var userIdentity register.RegisteredIdentity
	var agentIdentity register.RegisteredIdentity

	addr, err := url.Parse(resolverAddress)
	if err != nil {
		return C.CString(fmt.Sprintf("FFI lib error: parsing resolver address failed: %+v", err))
	}
	resolver := register.NewDefaultRestResolverClient(addr)

	agentDid := C.GoString(cAgentDid)
	agentKeyName := C.GoString(cAgentKeyName)
	agentName := C.GoString(cAgentName)
	agentSeed := C.GoString(cAgentSeed)

	agentIdentity, _, err = getIdentity(api.GetAgentIdentity, agentDid, agentKeyName, agentName, agentSeed)
	if err != nil {
		return C.CString(fmt.Sprintf("FFI lib error: failed to get agent registered identity: %+v", err))
	}

	userDid := C.GoString(cUserDid)
	userKeyName := C.GoString(cUserKeyName)
	userName := C.GoString(cUserName)
	userSeed := C.GoString(cUserSeed)

	userIdentity, _, err = getIdentity(api.GetUserIdentity, userDid, userKeyName, userName, userSeed)
	if err != nil {
		return C.CString(fmt.Sprintf("FFI lib error: failed to get agent registered identity: %+v", err))
	}

	err = api.UserDelegatesAuthenticationToAgent(resolver, userIdentity, agentIdentity, delegationName)

	if err != nil {
		return C.CString(fmt.Sprintf("FFI lib error: unable to delegate control to agent: %+v", err))
	}
	return C.CString("")
}

//export TwinDelegatesControlToAgent
func TwinDelegatesControlToAgent(cResolverAddress *C.char,
	cAgentDid *C.char,
	cAgentKeyName *C.char,
	cAgentName *C.char,
	cAgentSeed *C.char,

	cTwinDid *C.char,
	cTwinKeyName *C.char,
	cTwinName *C.char,
	cTwinSeed *C.char,

	cDelegationName *C.char) *C.char {

	resolverAddress := C.GoString(cResolverAddress)
	delegationName := C.GoString(cDelegationName)

	var twinIdentity register.RegisteredIdentity
	var agentIdentity register.RegisteredIdentity

	addr, err := url.Parse(resolverAddress)
	if err != nil {
		return C.CString(fmt.Sprintf("FFI lib error: parsing resolver address failed: %+v", err))
	}
	resolver := register.NewDefaultRestResolverClient(addr)

	agentDid := C.GoString(cAgentDid)
	agentKeyName := C.GoString(cAgentKeyName)
	agentName := C.GoString(cAgentName)
	agentSeed := C.GoString(cAgentSeed)

	agentIdentity, _, err = getIdentity(api.GetAgentIdentity, agentDid, agentKeyName, agentName, agentSeed)
	if err != nil {
		return C.CString(fmt.Sprintf("FFI lib error: failed to get agent registered identity: %+v", err))
	}

	twinDid := C.GoString(cTwinDid)
	twinKeyName := C.GoString(cTwinKeyName)
	twinName := C.GoString(cTwinName)
	twinSeed := C.GoString(cTwinSeed)

	twinIdentity, _, err = getIdentity(api.GetTwinIdentity, twinDid, twinKeyName, twinName, twinSeed)
	if err != nil {
		return C.CString(fmt.Sprintf("FFI lib error: failed to get agent registered identity: %+v", err))
	}

	err = api.TwinDelegatesControlToAgent(resolver, twinIdentity, agentIdentity, delegationName)

	if err != nil {
		return C.CString(fmt.Sprintf("FFI lib error: unable to delegate control to agent: %+v", err))
	}
	return C.CString("")
}

//export CreateAgentAuthToken
// CreateAgentAuthToken creates an Agent Authentication token given the secrets
// It returns the token string or error string
func CreateAgentAuthToken(
	cAgentDid *C.char, cAgentKeyName *C.char, cAgentName *C.char, cUserDid *C.char, cSeed *C.char, duration int64,
) (*C.char, *C.char) {

	// validation
	agentDid := C.GoString(cAgentDid)
	agentKeyName := C.GoString(cAgentKeyName)
	agentName := C.GoString(cAgentName)
	userDid := C.GoString(cUserDid)
	seed := C.GoString(cSeed)

	agent, _, err := getIdentity(api.GetAgentIdentity, agentDid, agentKeyName, agentName, seed)
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
	cResolverAddress *C.char,
	cAgentDid *C.char,
	cAgentKeyName *C.char,
	cAgentName *C.char,
	cAgentSeed *C.char,
	cTwinKeyName *C.char,
	cTwinName *C.char) (*C.char, *C.char) {

	// validation
	resolverAddress := C.GoString(cResolverAddress)
	agentDid := C.GoString(cAgentDid)
	agentKeyName := C.GoString(cAgentKeyName)
	agentName := C.GoString(cAgentName)
	agentSeed := C.GoString(cAgentSeed)
	twinKeyName := C.GoString(cTwinKeyName)
	twinName := C.GoString(cTwinName)

	addr, err := url.Parse(resolverAddress)
	if err != nil {
		return C.CString(""), C.CString(fmt.Sprintf("FFI lib error: parsing resolver address failed: %+v", err))
	}
	resolver := register.NewDefaultRestResolverClient(addr)
	agent, seedBytes, err := getIdentity(api.GetAgentIdentity, agentDid, agentKeyName, agentName, agentSeed)
	if err != nil {
		return C.CString(""), C.CString(fmt.Sprintf("FFI lib error: failed to get agent registered identity: %+v", err))
	}
	opts := &api.CreateTwinOpts{
		Seed:           seedBytes,
		KeyName:        twinKeyName,
		Name:           twinName,
		AgentID:        agent,
		DelegationName: "#TwinToAgentControlDeleg",
	}
	twinIdentity, err := api.CreateTwinWithControlDelegation(resolver, opts)
	if err != nil {
		return C.CString(""), C.CString(fmt.Sprintf("FFI lib error: creating twin DiD Doc failed: %+vs", err))
	}
	return C.CString(twinIdentity.Did()), C.CString("")
}

//export FreeUpCString
func FreeUpCString(pointer *C.char) {
	C.free(unsafe.Pointer(pointer))
}

func createIdentity(isUser bool, // true for userId, false for agentId
	cResolverAddress *C.char, cKeyName *C.char, cName *C.char, cSeed *C.char,
) (*C.char, *C.char) {
	var err error
	resolverAddress := C.GoString(cResolverAddress)
	keyName := C.GoString(cKeyName)
	name := C.GoString(cName)
	seed := C.GoString(cSeed)

	seedBytes, err := hex.DecodeString(seed)
	if err != nil {
		return C.CString(""), C.CString(fmt.Sprintf("FFI lib error: failed to decode seed: %+v", err))
	}
	addr, err := url.Parse(resolverAddress)
	if err != nil {
		return C.CString(""), C.CString(fmt.Sprintf("FFI lib error: parsing resolver address failed: %+v", err))
	}

	opts := &api.CreateIdentityOpts{
		Seed:    seedBytes,
		KeyName: keyName,
		//Password: nil,
		Name:     name,
		Method:   crypto.SeedMethodBip39,
		Override: true,
	}

	fmt.Printf("seed %v", seed)
	fmt.Printf("opts %v", opts)

	resolver := register.NewDefaultRestResolverClient(addr)
	var id register.RegisteredIdentity
	if isUser {
		id, err = api.CreateUserIdentity(resolver, opts)
	} else {
		id, err = api.CreateAgentIdentity(resolver, opts)
	}

	if err != nil {
		return C.CString(""), C.CString(fmt.Sprintf("FFI lib error: unable to create identity: %+v", err))
	}

	return C.CString(id.Did()), C.CString("")
}

func getIdentity(idFunc GetIDFunc,
	theDid string, theKeyName string, theName string, seed string,
) (register.RegisteredIdentity, []byte, error) {
	seedBytes, err := hex.DecodeString(seed)
	if err != nil {
		return nil, nil, err
	}
	opts := &api.GetIdentityOpts{
		Seed:    seedBytes,
		Did:     theDid,
		KeyName: theKeyName,
		Name:    theName,
		Method:  crypto.SeedMethodBip39,
	}
	agent, err := idFunc(opts)
	if err != nil {
		return nil, nil, err
	}
	did, err := identity.MakeIdentifier(agent.KeyPair().PublicKeyBytes)
	if err != nil {
		return nil, nil, err
	}
	if did != theDid {
		opts.Method = crypto.SeedMethodNone
		agent, err = idFunc(opts)
		if err != nil {
			return nil, nil, err
		}
	}
	return agent, seedBytes, nil
}

func main() {}
