# Build & run

1. go to the ffi directory and run the Makefile or the build.ps1 as per README.
2. once the build of the ffi wrapper works, copy the libraries in this top directory `copy .\lib\*.* .\dotnet-idsdk\IoticsIdLib\`
    - the libraries need to be made available to the project. there should be a way to configure the path in the csproj but I haven't found a way yet
3. run
    - `dotnet clean` to clean the project (sometimes it seems you need to delete the directories `bin` and `obj` manually)
    - `dotnet build` to build it
    - `dotnet run` to run the Main method in `src\Main.cs`

In order to distribute the project to 3rd parties you should zip the two files `lib-iotics-id-sdk.[dll|h]` and the content of the bin directory.


## Run output

a working output for the run is 

    A new seed: b7778a197751d2370662c03ba7b17a38224748729158437be98a185eeae69561
    Use these mnemonics instead of remembering the seed: resist rough main upgrade brush breeze book fix desert diesel future icon caught picnic ski climb drop tent glad cost upgrade infant few diagram
    Recovered seed: b7778a197751d2370662c03ba7b17a38224748729158437be98a185eeae69561
    Agent identity: Key=agentKeyName, Id=#agentName, Did=did:iotics:iotU1NapzbKmJC7b18UbohQe1HRpkGSYtnF6, Seed=...69561 Resolver=https://did.dev.iotics.com
    User identity: Key=userKeyName, Id=#userName, Did=did:iotics:iotDRfBoB4H1o7XRySDNQjppBP1YcDkwgEUN, Seed=...69561 Resolver=https://did.dev.iotics.com
    Twin identity: Key=userKeyName, Id=#userName, Did=did:iotics:iotWTs39Ce4cT85eXMGKsmS6rR8F73VGGxpu, Seed=...69561 Resolver=https://did.dev.iotics.com
    Twin identity with CD: Key=twinKeyName, Id=#twinName, Did=did:iotics:iotB8Jq3V1MyejYJercDmiXXZzZ1ZStVgi2o, Seed=...69561 Resolver=https://did.dev.iotics.com
    User delegating to agent 1: OK
    Agent2 identity: Key=agentKeyName2, Id=#agentName2, Did=did:iotics:iotGbUUVGm2kFBEhV49ZBzjk8vCb5MYLBGwK, Seed=...a2772 Resolver=https://did.dev.iotics.com
    Twin delegating to agent2: OK
    Token 1: eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJhdWQiOiJmb28iLCJleHAiOjE3MDcxMzIxNjcsImlhdCI6MTcwNzEzMjEyNywiaXNzIjoiZGlkOmlvdGljczppb3RVMU5hcHpiS21KQzdiMThVYm9oUWUxSFJwa0dTWXRuRjYjYWdlbnROYW1lIiwic3ViIjoiZGlkOmlvdGljczppb3REUmZCb0I0SDFvN1hSeVNETlFqcHBCUDFZY0Rrd2dFVU4ifQ.VxOhfy6a7cR8RzeEwMrPC9hqoyKLhRDxTMWAybN35SWhPDHzPDnjvORSFEpeovelD1XFRn9ikyLncygipZ9SVw
    Token 2: eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJhdWQiOiJmb28iLCJleHAiOjE3MDcxMzIxNjcsImlhdCI6MTcwNzEzMjEyNywiaXNzIjoiZGlkOmlvdGljczppb3RVMU5hcHpiS21KQzdiMThVYm9oUWUxSFJwa0dTWXRuRjYjYWdlbnROYW1lIiwic3ViIjoiZGlkOmlvdGljczppb3REUmZCb0I0SDFvN1hSeVNETlFqcHBCUDFZY0Rrd2dFVU4ifQ.0qNDZRJEvExnGEphi6RuZj3t_MnL7HXs0PgrR-rsWHL3Px8MXGxDo75WSlwbaABaLrCErvKgmk-cV_AX-oGJgQ
