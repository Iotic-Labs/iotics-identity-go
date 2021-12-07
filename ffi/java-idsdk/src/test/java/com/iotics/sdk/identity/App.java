package com.iotics.sdk.identity;

import com.iotics.sdk.identity.jna.JnaSdkApiInitialiser;
import com.iotics.sdk.identity.jna.SdkApi;

import java.time.Duration;

public class App {
    static String resolver = "https://did.stg.iotics.com";
    static String seed = "f25a09c9d21ad5f7535fac4c30afe1a9f2ca025a192db549044b1b0130d1e945";
    static String uDiD = "did:iotics:iotEBuXp2wHMREZmwYAyPhFzPYfWtt9Ka2R2";
    static Identity agentIdentity = new Identity("aKey1", "#app1", "did:iotics:iotJxn2AHBkaFXKkBymbFYcVokGhLShLtUf1");

    public static void main(String[] args) {
        SdkApi api = new JnaSdkApiInitialiser("../bin/lib-iotics-id-sdk-amd64.so").get();
        delegation(api);
    }

    public static void delegation(SdkApi api) {
        SimpleIdentity idSdk = new SimpleIdentity(api, resolver, seed);

        Identity userIdentity = idSdk.CreateUserIdentity("uKey1", "#user1");
        System.out.println("CreateUserIdentity: " + userIdentity);
        System.out.println("Agent identity: " + agentIdentity);
        idSdk.UserDelegatesAuthenticationToAgent(agentIdentity, userIdentity, "delegation1");

        Identity twinIdentity = idSdk.CreateTwinIdentityWithControlDelegation(agentIdentity, "tKey1", "#tName");
        System.out.println("CreateTwinDidWithControlDelegation: " + twinIdentity);

        Identity anotherAgentIdentity = idSdk.CreateAgentIdentity("aKey1", "#app2");
        System.out.println("CreateAgentIdentity: " + anotherAgentIdentity);

        idSdk.TwinDelegatesControlToAgent(anotherAgentIdentity, twinIdentity, "delegation2");
    }


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

}