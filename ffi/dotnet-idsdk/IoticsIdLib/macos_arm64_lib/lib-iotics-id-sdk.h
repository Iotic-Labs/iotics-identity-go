/* Code generated by cmd/cgo; DO NOT EDIT. */

/* package command-line-arguments */


#line 1 "cgo-builtin-export-prolog"

#include <stddef.h>

#ifndef GO_CGO_EXPORT_PROLOGUE_H
#define GO_CGO_EXPORT_PROLOGUE_H

#ifndef GO_CGO_GOSTRING_TYPEDEF
typedef struct { const char *p; ptrdiff_t n; } _GoString_;
#endif

#endif

/* Start of preamble from import "C" comments.  */


#line 3 "ffi_wrapper.go"
 #include <stdio.h>
 #include <errno.h>
 #include <stdlib.h>

#line 1 "cgo-generated-wrapper"


/* End of preamble from import "C" comments.  */


/* Start of boilerplate cgo prologue.  */
#line 1 "cgo-gcc-export-header-prolog"

#ifndef GO_CGO_PROLOGUE_H
#define GO_CGO_PROLOGUE_H

typedef signed char GoInt8;
typedef unsigned char GoUint8;
typedef short GoInt16;
typedef unsigned short GoUint16;
typedef int GoInt32;
typedef unsigned int GoUint32;
typedef long long GoInt64;
typedef unsigned long long GoUint64;
typedef GoInt64 GoInt;
typedef GoUint64 GoUint;
typedef size_t GoUintptr;
typedef float GoFloat32;
typedef double GoFloat64;
#ifdef _MSC_VER
#include <complex.h>
typedef _Fcomplex GoComplex64;
typedef _Dcomplex GoComplex128;
#else
typedef float _Complex GoComplex64;
typedef double _Complex GoComplex128;
#endif

/*
  static assertion to make sure the file is being used on architecture
  at least with matching size of GoInt.
*/
typedef char _check_for_64_bit_pointer_matching_GoInt[sizeof(void*)==64/8 ? 1:-1];

#ifndef GO_CGO_GOSTRING_TYPEDEF
typedef _GoString_ GoString;
#endif
typedef void *GoMap;
typedef void *GoChan;
typedef struct { void *t; void *v; } GoInterface;
typedef struct { void *data; GoInt len; GoInt cap; } GoSlice;

#endif

/* End of boilerplate cgo prologue.  */

#ifdef __cplusplus
extern "C" {
#endif


/* Return type for CreateDefaultSeed */
struct CreateDefaultSeed_return {
	char* r0;
	char* r1;
};
extern struct CreateDefaultSeed_return CreateDefaultSeed();

/* Return type for MnemonicBip39ToSeed */
struct MnemonicBip39ToSeed_return {
	char* r0;
	char* r1;
};
extern struct MnemonicBip39ToSeed_return MnemonicBip39ToSeed(char* cMnemonic);

/* Return type for SeedBip39ToMnemonic */
struct SeedBip39ToMnemonic_return {
	char* r0;
	char* r1;
};
extern struct SeedBip39ToMnemonic_return SeedBip39ToMnemonic(char* cSeed);

/* Return type for CreateAgentIdentity */
struct CreateAgentIdentity_return {
	char* r0;
	char* r1;
};
extern struct CreateAgentIdentity_return CreateAgentIdentity(char* cResolverAddress, char* cKeyName, char* cName, char* cSeed);

/* Return type for RecreateAgentIdentity */
struct RecreateAgentIdentity_return {
	char* r0;
	char* r1;
};
extern struct RecreateAgentIdentity_return RecreateAgentIdentity(char* cResolverAddress, char* cKeyName, char* cName, char* cSeed);

/* Return type for CreateUserIdentity */
struct CreateUserIdentity_return {
	char* r0;
	char* r1;
};
extern struct CreateUserIdentity_return CreateUserIdentity(char* cResolverAddress, char* cKeyName, char* cName, char* cSeed);

/* Return type for RecreateUserIdentity */
struct RecreateUserIdentity_return {
	char* r0;
	char* r1;
};
extern struct RecreateUserIdentity_return RecreateUserIdentity(char* cResolverAddress, char* cKeyName, char* cName, char* cSeed);

/* Return type for CreateTwinIdentity */
struct CreateTwinIdentity_return {
	char* r0;
	char* r1;
};
extern struct CreateTwinIdentity_return CreateTwinIdentity(char* cResolverAddress, char* cKeyName, char* cName, char* cSeed);

/* Return type for RecreateTwinIdentity */
struct RecreateTwinIdentity_return {
	char* r0;
	char* r1;
};
extern struct RecreateTwinIdentity_return RecreateTwinIdentity(char* cResolverAddress, char* cKeyName, char* cName, char* cSeed);
extern char* UserDelegatesAuthenticationToAgent(char* cResolverAddress, char* cAgentDid, char* cAgentKeyName, char* cAgentName, char* cAgentSeed, char* cUserDid, char* cUserKeyName, char* cUserName, char* cUserSeed, char* cDelegationName);
extern char* TwinDelegatesControlToAgent(char* cResolverAddress, char* cAgentDid, char* cAgentKeyName, char* cAgentName, char* cAgentSeed, char* cTwinDid, char* cTwinKeyName, char* cTwinName, char* cTwinSeed, char* cDelegationName);

/* Return type for IsAllowedFor */
struct IsAllowedFor_return {
	char* r0;
	char* r1;
};
extern struct IsAllowedFor_return IsAllowedFor(char* cResolverAddress, char* cToken);

/* Return type for CreateAgentAuthToken */
struct CreateAgentAuthToken_return {
	char* r0;
	char* r1;
};

// CreateAgentAuthToken creates an Agent Authentication token given the secrets
// It returns the token string or error string
//
extern struct CreateAgentAuthToken_return CreateAgentAuthToken(char* cAgentDid, char* cAgentKeyName, char* cAgentName, char* cAgentSeed, char* cUserDid, char* cAudience, GoInt64 durationInSeconds);

/* Return type for CreateTwinDidWithControlDelegation */
struct CreateTwinDidWithControlDelegation_return {
	char* r0;
	char* r1;
};
extern struct CreateTwinDidWithControlDelegation_return CreateTwinDidWithControlDelegation(char* cResolverAddress, char* cAgentDid, char* cAgentKeyName, char* cAgentName, char* cAgentSeed, char* cTwinKeyName, char* cTwinName);
extern void FreeUpCString(char* pointer);

#ifdef __cplusplus
}
#endif
