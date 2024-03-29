package main

// #include <stdio.h>
// #include <errno.h>
// #include <stdlib.h>
import "C"
import (
	"context"
	"encoding/hex"
	"fmt"
	"net/url"
	"strings"
	"time"
	"unsafe"

	"github.com/Iotic-Labs/iotics-identity-go/v3/pkg/api"
	"github.com/Iotic-Labs/iotics-identity-go/v3/pkg/crypto"
	"github.com/Iotic-Labs/iotics-identity-go/v3/pkg/identity"
	"github.com/Iotic-Labs/iotics-identity-go/v3/pkg/register"
)

type GetIDFunc = func(opts *api.GetIdentityOpts) (register.RegisteredIdentity, error)

type idDocType int

const ( // iota is reset to 0
	idDocUser  idDocType = iota // 0
	idDocAgent           = iota // 1
	idDocTwin            = iota // 2
)

//export CreateDefaultSeed
func CreateDefaultSeed() (*C.char, *C.char) {
	res, err := api.CreateDefaultSeed()
	if err != nil {
		return nil, C.CString(fmt.Sprintf("FFI lib error: failed to create default length seed: %+v", err))
	}
	return C.CString(hex.EncodeToString(res)), nil
}

//export MnemonicBip39ToSeed
func MnemonicBip39ToSeed(cMnemonic *C.char) (*C.char, *C.char) {
	mnemonic := C.GoString(cMnemonic)
	res, err := crypto.MnemonicBip39ToSeed(mnemonic)
	if err != nil {
		return nil, C.CString(fmt.Sprintf("FFI lib error: failed to create default length seed: %+v", err))
	}
	return C.CString(hex.EncodeToString(res)), nil
}

//export SeedBip39ToMnemonic
func SeedBip39ToMnemonic(cSeed *C.char) (*C.char, *C.char) {
	seedBytes, err := hex.DecodeString(C.GoString(cSeed))
	if err != nil {
		return nil, C.CString(fmt.Sprintf("FFI lib error: failed to decode seed: %+v", err))
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
	return createIdentity(idDocAgent, cResolverAddress, cKeyName, cName, cSeed, false)
}

//export RecreateAgentIdentity
func RecreateAgentIdentity(cResolverAddress *C.char, cKeyName *C.char, cName *C.char, cSeed *C.char,
) (*C.char, *C.char) {
	return createIdentity(idDocAgent, cResolverAddress, cKeyName, cName, cSeed, true)
}

//export CreateUserIdentity
func CreateUserIdentity(cResolverAddress *C.char, cKeyName *C.char, cName *C.char, cSeed *C.char,
) (*C.char, *C.char) {
	return createIdentity(idDocUser, cResolverAddress, cKeyName, cName, cSeed, false)
}

//export RecreateUserIdentity
func RecreateUserIdentity(cResolverAddress *C.char, cKeyName *C.char, cName *C.char, cSeed *C.char,
) (*C.char, *C.char) {
	return createIdentity(idDocUser, cResolverAddress, cKeyName, cName, cSeed, true)
}

//export CreateTwinIdentity
func CreateTwinIdentity(cResolverAddress *C.char, cKeyName *C.char, cName *C.char, cSeed *C.char,
) (*C.char, *C.char) {
	return createIdentity(idDocTwin, cResolverAddress, cKeyName, cName, cSeed, false)
}

//export RecreateTwinIdentity
func RecreateTwinIdentity(cResolverAddress *C.char, cKeyName *C.char, cName *C.char, cSeed *C.char,
) (*C.char, *C.char) {
	return createIdentity(idDocTwin, cResolverAddress, cKeyName, cName, cSeed, true)
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

	cDelegationName *C.char,
) *C.char {

	ctx := context.TODO()

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

	err = api.UserDelegatesAuthenticationToAgent(ctx, resolver, userIdentity, agentIdentity, delegationName)

	if err != nil {
		return C.CString(fmt.Sprintf("FFI lib error: unable to delegate control to agent: %+v", err))
	}
	return nil
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

	ctx := context.TODO()

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

	err = api.TwinDelegatesControlToAgent(ctx, resolver, twinIdentity, agentIdentity, delegationName)

	if err != nil {
		return C.CString(fmt.Sprintf("FFI lib error: unable to delegate control to agent: %+v", err))
	}
	return nil
}

//export IsAllowedFor
func IsAllowedFor(
	cResolverAddress *C.char,
	cToken *C.char,
) (*C.char, *C.char) {
	ctx := context.TODO()

	resolverAddress := C.GoString(cResolverAddress)
	rAdd, err := url.Parse(resolverAddress)
	if err != nil {
		return nil, C.CString("FFI lib error: resolver address invalid")
	}
	resolver := register.NewDefaultRestResolverClient(rAdd)

	token := C.GoString(cToken)
	authToken := register.JwtToken(token)
	claims, err := register.DecodeAuthTokenNoVerify(authToken)
	if err != nil {
		return nil, C.CString(fmt.Sprintf("FFI lib error: error with token verification: %v", err))
	}
	userDid := claims.Subject
	agentDid := claims.Issuer.Did
	agentDoc, err := resolver.GetDocument(ctx, agentDid)
	if err != nil {
		return nil, C.CString(fmt.Sprintf("FFI lib error: unable to fetch agent document: %v", err))
	}
	userDoc, err := resolver.GetDocument(ctx, userDid)

	if err != nil {
		return nil, C.CString(fmt.Sprintf("FFI lib error: unable to fetch user document: %v", err))
	}

	allowed, err := register.IsAllowFor(ctx, resolver, claims.Issuer, agentDoc, userDoc, true)
	if err != nil {
		return nil, C.CString(fmt.Sprintf("FFI lib error: unable to determine result: %v", err))
	}
	return C.CString(fmt.Sprintf("%v", allowed)), nil

}

// CreateAgentAuthToken creates an Agent Authentication token given the secrets
// It returns the token string or error string
//
//export CreateAgentAuthToken
func CreateAgentAuthToken(

	cAgentDid *C.char,
	cAgentKeyName *C.char,
	cAgentName *C.char,
	cAgentSeed *C.char,

	cUserDid *C.char,

	cAudience *C.char,

	durationInSeconds int64) (*C.char, *C.char) {

	// validation
	agentDid := C.GoString(cAgentDid)
	agentKeyName := C.GoString(cAgentKeyName)
	agentName := C.GoString(cAgentName)
	agentSeed := C.GoString(cAgentSeed)
	userDid := C.GoString(cUserDid)
	audience := C.GoString(cAudience)

	// an empty audience will break token validation.
	// the sdk isn't fully validating audience though so for now we just check
	// whether it's empty or not
	if strings.TrimSpace(audience) == "" {
		return nil, C.CString("FFI lib error: audience can't be empty")
	}

	agent, _, err := getIdentity(api.GetAgentIdentity, agentDid, agentKeyName, agentName, agentSeed)

	if err != nil {
		return nil, C.CString(fmt.Sprintf("FFI lib error: failed to get agent registered identity: %+v", err))
	}

	token, err := api.CreateAgentAuthToken(agent, userDid, time.Duration(durationInSeconds)*time.Second, audience)
	if err != nil {
		return nil, C.CString(fmt.Sprintf("FFI lib error: failed to get token: %+v", err))
	}

	return C.CString(string(token)), nil
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

	ctx := context.TODO()

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
		return nil, C.CString(fmt.Sprintf("FFI lib error: parsing resolver address failed: %+v", err))
	}
	resolver := register.NewDefaultRestResolverClient(addr)
	agent, seedBytes, err := getIdentity(api.GetAgentIdentity, agentDid, agentKeyName, agentName, agentSeed)
	if err != nil {
		return nil, C.CString(fmt.Sprintf("FFI lib error: failed to get agent registered identity: %+v", err))
	}
	opts := &api.CreateTwinOpts{
		Seed:           seedBytes,
		KeyName:        twinKeyName,
		Name:           twinName,
		AgentID:        agent,
		DelegationName: "#TwinToAgentControlDeleg",
	}
	twinIdentity, err := api.CreateTwinWithControlDelegation(ctx, resolver, opts)
	if err != nil {
		return nil, C.CString(fmt.Sprintf("FFI lib error: creating twin DiD Doc failed: %+v", err))
	}
	return C.CString(twinIdentity.Did()), nil
}

//export FreeUpCString
func FreeUpCString(pointer *C.char) {
	C.free(unsafe.Pointer(pointer))
}

func createIdentity(
	idDoc idDocType,
	cResolverAddress *C.char,
	cKeyName *C.char,
	cName *C.char,
	cSeed *C.char,
	override bool,
) (*C.char, *C.char) {
	ctx := context.TODO()

	resolverAddress := C.GoString(cResolverAddress)
	keyName := C.GoString(cKeyName)
	name := C.GoString(cName)
	seed := C.GoString(cSeed)

	seedBytes, err := hex.DecodeString(seed)
	if err != nil {
		return nil, C.CString(fmt.Sprintf("FFI lib error: failed to decode seed: %+v", err))
	}
	addr, err := url.Parse(resolverAddress)
	if err != nil {
		return nil, C.CString(fmt.Sprintf("FFI lib error: parsing resolver address failed: %+v", err))
	}

	opts := &api.CreateIdentityOpts{
		Seed:    seedBytes,
		KeyName: keyName,
		//Password: nil,
		Name:     name,
		Method:   crypto.SeedMethodBip39,
		Override: override,
	}

	resolver := register.NewDefaultRestResolverClient(addr)
	var id register.RegisteredIdentity
	if idDoc == idDocUser {
		id, err = api.CreateUserIdentity(ctx, resolver, opts)
	} else if idDoc == idDocAgent {
		id, err = api.CreateAgentIdentity(ctx, resolver, opts)
	} else if idDoc == idDocTwin {
		id, err = api.CreateTwinIdentity(ctx, resolver, opts)
	} else {
		return nil, C.CString(fmt.Sprintf("FFI lib error: unsupported identity type: %+v", idDoc))
	}

	if err != nil {
		return nil, C.CString(fmt.Sprintf("FFI lib error: unable to create identity: %+v", err))
	}

	return C.CString(id.Did()), nil
}

func getIdentity(idFunc GetIDFunc, theDid string, theKeyName string, theName string, seed string) (register.RegisteredIdentity, []byte, error) {
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
