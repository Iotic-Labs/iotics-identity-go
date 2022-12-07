package com.iotics.sdk.identity;

import com.iotics.sdk.identity.jna.SdkApi;
import com.iotics.sdk.identity.resolver.HttpResolverClient;

import java.net.MalformedURLException;
import java.net.URI;
import java.net.URL;
import java.time.Duration;
import java.util.Objects;

import static com.iotics.sdk.identity.Validator.getValueOrThrow;
import static com.iotics.sdk.identity.Validator.throwIfNotNull;

public class SimpleIdentity {
    private final SdkApi api;
    private final String userSeed;
    private final String agentSeed;
    private final URL resolverAddress;
    private final HttpResolverClient resolverClient;

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
        try {
            this.resolverAddress = URI.create(resolverAddress).toURL();
            this.resolverClient = new HttpResolverClient(this.resolverAddress);
        } catch (MalformedURLException e) {
            throw new IllegalArgumentException("resolver address not a valid URL: " + resolverAddress);
        }
    }

    public Identity CreateAgentIdentity(String keyName, String name) {
        String did = getValueOrThrow(api.CreateAgentIdentity(resolverAddress.toString(), keyName, name, agentSeed));
        return new Identity(keyName, name, did);
    }

    public Identity RecreateAgentIdentity(String keyName, String name) {
        String did = getValueOrThrow(api.RecreateAgentIdentity(resolverAddress.toString(), keyName, name, agentSeed));
        return new Identity(keyName, name, did);
    }

    public Identity CreateUserIdentity(String keyName, String name) {
        String did = getValueOrThrow(api.CreateUserIdentity(resolverAddress.toString(), keyName, name, userSeed));
        return new Identity(keyName, name, did);
    }

    public Identity RecreateUserIdentity(String keyName, String name) {
        String did = getValueOrThrow(api.RecreateUserIdentity(resolverAddress.toString(), keyName, name, userSeed));
        return new Identity(keyName, name, did);
    }

    public Identity CreateTwinIdentityWithControlDelegation(Identity agentIdentity, String twinKeyName, String twinName) {
        String did = getValueOrThrow(api.CreateTwinDidWithControlDelegation(resolverAddress.toString(),
                agentIdentity.did(), agentIdentity.keyName(), agentIdentity.name(), agentSeed, twinKeyName, twinName));
        return new Identity(twinKeyName, twinName, did);
    }

    public String CreateAgentAuthToken(Identity agentIdentity, String userDid, String audience, Duration duration) {
        return getValueOrThrow(api.CreateAgentAuthToken(
                agentIdentity.did(), agentIdentity.keyName(), agentIdentity.name(), agentSeed, userDid, audience, duration.toSeconds()));
    }

    public String CreateAgentAuthToken(Identity agentIdentity, String userDid, Duration duration) {
        return CreateAgentAuthToken(agentIdentity, userDid, resolverAddress.toString(), duration);
    }

    public String RecreateAgentAuthToken(Identity agentIdentity, String userDid, String audience, Duration duration) {
        return getValueOrThrow(api.CreateAgentAuthToken(
                agentIdentity.did(), agentIdentity.keyName(), agentIdentity.name(), agentSeed, userDid, audience, duration.toSeconds()));
    }

    public String RecreateAgentAuthToken(Identity agentIdentity, String userDid, Duration duration) {
        return CreateAgentAuthToken(agentIdentity, userDid, resolverAddress.toString(), duration);
    }

    public String IsAllowedFor(String resolverAddress, String token) {
        return getValueOrThrow(api.IsAllowedFor(resolverAddress, token));
    }

    public void UserDelegatesAuthenticationToAgent(Identity agentId, Identity userId, String delegationName) {
        throwIfNotNull(api.UserDelegatesAuthenticationToAgent(resolverAddress.toString(),
                agentId.did(), agentId.keyName(), agentId.name(), agentSeed,
                userId.did(), userId.keyName(), userId.name(), userSeed, delegationName));

    }

    public void TwinDelegatesControlToAgent(Identity agentId, Identity twinId, String delegationName) {
        throwIfNotNull(api.TwinDelegatesControlToAgent(resolverAddress.toString(),
                agentId.did(), agentId.keyName(), agentId.name(), agentSeed,
                twinId.did(), twinId.keyName(), twinId.name(), agentSeed, delegationName));
    }

    String getAgentSeed() {
        return agentSeed;
    }

    String getUserSeed() {
        return userSeed;
    }

    public URL getResolverAddress() {
        return resolverAddress;
    }
}
