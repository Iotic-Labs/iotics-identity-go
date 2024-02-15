# Dotnet Library for Iotics Identity Library

This document outlines the process for building, running, and distributing a .NET library that interfaces with the Iotics Identity Library. The library facilitates operations related to digital identities in the Iotics ecosystem.

## Prerequisites
Before you begin, ensure you have the following prerequisites:

* .NET SDK (version specifying if needed, e.g., .NET 5.0)
* Appropriate permissions to access https://<myspace>.iotics.space/index.json to retrieve the resolver addresses
* A copy of the Identity Library available in `./dotnet-idsdk/IoticsIdLib`. You can build it following instructions in `./ffi/README.md` or download it from https://github.com/Iotic-Labs/iotics-identity-go/tags

## Build the library and test application

* `dotnet clean`
    * cleans the project; sometimes it seems you need to delete the directories `bin` and `obj` manually
* `dotnet build`
    * builds the library and test application in `./bin` 
* `dotnet run <resolver address>` to run the Main method in `src/Main.cs`
    * retrieve the resolver address from `https://<myspace>.iotics.space/index.json`

## Distribution
To distribute this project to third parties, include:

* Binary and header files named lib-iotics-id-sdk.*
* The contents of the bin directory after building the project

## Example Run output

The `src/Main.cs` shows an example of how to use the library to perform high level basic functions with the Identity Library.

An example working output for the run is 

    A new seed: ...69561
    Use these mnemonics instead of remembering the seed: resist rough main ...
    Recovered seed: ...69561
    ...
    Token 2: eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9....gmk-cV_AX-oGJgQ

Any execution errors will terminate the application with a non-zero return code, accompanied by an error message.

### Troubleshooting 

#### Resolver Not Reachable:

    Error: FFI lib error: unable to create identity: Get "https://domain.resolver": dial tcp: lookup domain.resolver: no such host

Ensure you have the correct resolver address and that your internet connection is stable.

#### Iotics Identity Library Not Found (Windows):

    Error: Exception when invoking method: Unable to load DLL 'lib-iotics-id-sdk' or one of its dependencies: The specified module could not be found. (0x8007007E)

Verify that the lib-iotics-id-sdk.* files are correctly placed in the project directory as instructed in the setup section.
