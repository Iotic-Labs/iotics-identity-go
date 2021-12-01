package com.iotics.sdk.identity;

import com.iotics.sdk.identity.go.StringResult;
import com.iotics.sdk.identity.jna.SdkApi;

public class SimpleIdentity {
    private final SdkApi api;
    private final String userSeed;
    private final String agentSeed;
    private final String resolverAddress;

    public SimpleIdentity(SdkApi api, String resolverAddress) {
        this(api, resolverAddress, getValueOrThrow(api.CreateDefaultSeed()));
    }

    public SimpleIdentity(SdkApi api, String resolverAddress, String seed) {
        this(api, resolverAddress, seed, seed);
    }

    public SimpleIdentity(SdkApi api, String resolverAddress, String userSeed, String agentSeed) {
        this.api = api;
        this.userSeed = userSeed;
        this.agentSeed = agentSeed;
        this.resolverAddress = resolverAddress;
        // TODO: validate
    }

    public String CreateDefaultSeed() {
        return getValueOrThrow(api.CreateDefaultSeed());
    }

    public String MnemonicBip39ToSeed(String mnemonics) {
        return getValueOrThrow(api.MnemonicBip39ToSeed(mnemonics));
    }

    public String SeedBip39ToMnemonic(String seed) {
        return getValueOrThrow(api.SeedBip39ToMnemonic(seed));
    }

    public Identity CreateAgentIdentity(String keyName, String name) {
        String did = getValueOrThrow(api.CreateAgentIdentity(resolverAddress, keyName, name, agentSeed));
        return new Identity(keyName, name, did);
    }

    public Identity CreateUserIdentity(String keyName, String name) {
        String did = getValueOrThrow(api.CreateUserIdentity(resolverAddress, keyName, name, userSeed));
        return new Identity(keyName, name, did);
    }

    public Identity CreateTwinDidWithControlDelegation(Identity agentIdentity, String twinKeyName, String twinName) {
        String did = getValueOrThrow(api.CreateTwinDidWithControlDelegation(resolverAddress,
                agentIdentity.did(), agentIdentity.keyName(), agentIdentity.name(), agentSeed, twinKeyName, twinName));
        return new Identity(twinKeyName, twinName, did);
    }

    private static String getValueOrThrow(StringResult ret) {
        if (ret.err != null) {
            throw new SimpleIdentityException(ret.err);
        }
        return ret.value;

    }

}
