package com.iotics.sdk.identity;

import com.iotics.sdk.identity.jna.JnaSdkApiInitialiser;
import com.iotics.sdk.identity.jna.SdkApi;

public class App {


    public static void main(String[] args) {

        SdkApi api = new JnaSdkApiInitialiser().get();
        String resolver = "https://did.stg.iotics.com";
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

        Identity twinIdentity = idSdk.CreateTwinDidWithControlDelegation(agentIdentity, "tKey1", "#tName");
        System.out.println("CreateTwinDidWithControlDelegation: " + twinIdentity);

    }

}