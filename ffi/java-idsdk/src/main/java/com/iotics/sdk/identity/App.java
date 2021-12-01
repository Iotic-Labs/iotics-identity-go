package com.iotics.sdk.identity;

import com.iotics.sdk.identity.jna.JnaSdkApiInitialiser;
import com.iotics.sdk.identity.jna.SdkApi;

public class App {


    public static void main(String[] args) {

        SdkApi api = new JnaSdkApiInitialiser().get();
        String resolver = "https://did.stg.iotics.com/";
        SimpleIdentity idSdk = new SimpleIdentity(api, resolver);

        String res;

        res = idSdk.CreateDefaultSeed();
        System.out.println("CreateDefaultSeed: " + res);

        res = idSdk.SeedBip39ToMnemonic(res);
        System.out.println("SeedBip39ToMnemonic: " + res);

        res = idSdk.MnemonicBip39ToSeed(res);
        System.out.println("MnemonicBip39ToSeed: " + res);

        res = idSdk.CreateAgentIdentity("aKey1", "#app1");
        System.out.println("CreateAgentIdentity: " + res);

        res = idSdk.CreateUserIdentity("uKey1", "#user1");
        System.out.println("CreateUserIdentity: " + res);
    }

}