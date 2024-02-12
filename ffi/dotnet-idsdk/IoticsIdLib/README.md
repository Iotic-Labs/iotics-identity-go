# Build

Go to the ffi directory and run the `Makefile` or the `build.ps1` as per README.

# Run the test Application

1. Copy the libraries built in this top directory. For example, for Windows `copy .\lib\*.* .\dotnet-idsdk\IoticsIdLib\` to make the libraries available to the project.  
2. Run
    - `dotnet clean` to clean the project (sometimes it seems you need to delete the directories `bin` and `obj` manually)
    - `dotnet build` to build it
    - `dotnet run <resolver address>` to run the Main method in `src\Main.cs` (you can find the resolver address from `https://<myspace>.iotics.space/index.json`)

In order to distribute the project to 3rd parties you should make the binary and header files `lib-iotics-id-sdk.*` and the content of the bin directory.

## Run output

An example working output for the run is 

    A new seed: ...69561
    Use these mnemonics instead of remembering the seed: resist rough main ...
    Recovered seed: ...69561
    Agent identity: Key=agentKeyName, Id=#agentName, Did=did:iotics:iotU1N..., Seed=...69561 Resolver=https://did.dev.iotics.com
    User identity: Key=userKeyName, Id=#userName, Did=did:iotics:iotDRfBoB..., Seed=...69561 Resolver=https://did.dev.iotics.com
    Twin identity: Key=userKeyName, Id=#userName, Did=did:iotics:iotWTs39C..., Seed=...69561 Resolver=https://did.dev.iotics.com
    Twin identity with CD: Key=twinKeyName, Id=#twinName, Did=did:iotics:iotB8Jq..., Seed=...69561 Resolver=https://did.dev.iotics.com
    User delegating to agent 1: OK
    Agent2 identity: Key=agentKeyName2, Id=#agentName2, Did=did:iotics:iotGbUU..., Seed=...a2772 Resolver=https://did.dev.iotics.com
    Twin delegating to agent2: OK
    Token 1: eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9....ikyLncygipZ9SVw
    Token 2: eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9....gmk-cV_AX-oGJgQ
