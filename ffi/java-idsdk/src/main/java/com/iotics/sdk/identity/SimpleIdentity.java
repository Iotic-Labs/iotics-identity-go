package com.iotics.sdk.identity;

import com.iotics.sdk.identity.jna.SdkApi;

import java.net.URI;
import java.time.Duration;
import java.util.Objects;

import static com.iotics.sdk.identity.Validator.getValueOrThrow;
import static com.iotics.sdk.identity.Validator.throwIfNotNull;

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
        this.api = Objects.requireNonNull(api);
        this.userSeed = Objects.requireNonNull(userSeed);
        this.agentSeed = Objects.requireNonNull(agentSeed);
        this.resolverAddress = URI.create(resolverAddress).toString();
    }

    public Identity CreateAgentIdentity(String keyName, String name) {
        String did = getValueOrThrow(api.CreateAgentIdentity(resolverAddress, keyName, name, agentSeed));
        return new Identity(keyName, name, did);
    }

    public Identity CreateUserIdentity(String keyName, String name) {
        String did = getValueOrThrow(api.CreateUserIdentity(resolverAddress, keyName, name, userSeed));
        return new Identity(keyName, name, did);
    }

    public Identity CreateTwinIdentityWithControlDelegation(Identity agentIdentity, String twinKeyName, String twinName) {
        String did = getValueOrThrow(api.CreateTwinDidWithControlDelegation(resolverAddress,
                agentIdentity.did(), agentIdentity.keyName(), agentIdentity.name(), agentSeed, twinKeyName, twinName));
        return new Identity(twinKeyName, twinName, did);
    }

    public String CreateAgentAuthToken(Identity agentIdentity, String userDid, Duration duration) {
        int secs = Math.toIntExact(duration.toSeconds());
        return getValueOrThrow(api.CreateAgentAuthToken(
                agentIdentity.did(), agentIdentity.keyName(), agentIdentity.name(), agentSeed, userDid, secs));
    }

    public void UserDelegatesAuthenticationToAgent(Identity agentId, Identity userId, String delegationName) {
        throwIfNotNull(api.UserDelegatesAuthenticationToAgent(resolverAddress,
                agentId.did(), agentId.keyName(), agentId.name(), agentSeed,
                userId.did(), userId.keyName(), userId.name(), userSeed, delegationName));

    }

    public void TwinDelegatesControlToAgent(Identity agentId, Identity twinId, String delegationName) {
        throwIfNotNull(api.TwinDelegatesControlToAgent(resolverAddress,
                agentId.did(), agentId.keyName(), agentId.name(), agentSeed,
                twinId.did(), twinId.keyName(), twinId.name(), agentSeed, delegationName));

    }




    String getAgentSeed() {
        return agentSeed;
    }

    String getUserSeed() {
        return userSeed;
    }
}
