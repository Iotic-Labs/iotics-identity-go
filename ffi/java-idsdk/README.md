# Java wrapper for the ID SDK

FFI wrapper using JNA

## Build

`$> mvn pakage`

## Test

A sample app is in the test/java directory: `com.iotics.sdk.identity.App`

## Use

```java
SdkApi api = new JnaSdkApiInitialiser("<path_to>/lib-iotics-id-sdk-amd64.so").get();

```

```java
    public static void token(SdkApi api) {
        SimpleIdentity idSdk = new SimpleIdentity(api, resolver, seed);
        String token = idSdk.CreateAgentAuthToken(agentIdentity, uDiD, Duration.ofHours(10));
        System.out.println("CreateAgentAuthToken: " + token);
    }

    public static void seeds(SdkApi api) {

        Seeds seeds = new Seeds(api);

        String res;

        res = seeds.CreateDefaultSeed();
        System.out.println("CreateDefaultSeed: " + res);

        res = seeds.SeedBip39ToMnemonic(res);
        System.out.println("SeedBip39ToMnemonic: " + res);

        res = seeds.MnemonicBip39ToSeed(res);
        System.out.println("MnemonicBip39ToSeed: " + res);

        SimpleIdentity idSdk = new SimpleIdentity(api, resolver);

        Identity agentIdentity = idSdk.CreateAgentIdentity("aKey1", "#app1");
        System.out.println("CreateAgentIdentity: " + agentIdentity );

        Identity userIdentity = idSdk.CreateUserIdentity("uKey1", "#user1");
        System.out.println("CreateUserIdentity: " + userIdentity);

        Identity twinIdentity = idSdk.CreateTwinIdentityWithControlDelegation(agentIdentity, "tKey1", "#tName");
        System.out.println("CreateTwinDidWithControlDelegation: " + twinIdentity);

    }
```
