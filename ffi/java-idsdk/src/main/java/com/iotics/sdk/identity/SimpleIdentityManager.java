package com.iotics.sdk.identity;


import com.iotics.sdk.identity.jna.JnaSdkApiInitialiser;
import com.iotics.sdk.identity.jna.SdkApi;

import java.time.Duration;

/**
 * High level class to manage a user and an agent identities plus wrapper methods to create token and twin
 */
public class SimpleIdentityManager implements IdentityManager {

    private final Identity agentIdentity;
    private final Identity userIdentity;
    private final SimpleIdentity idSdk;

    private SimpleIdentityManager(String resolverAddress,
                                  String userSeed, String agentSeed,
                                  String userKeyName, String userKeyID,
                                  String agentKeyName, String agentKeyID,
                                  String authDelegationID) {
        SdkApi api = new JnaSdkApiInitialiser().get();
        idSdk = new SimpleIdentity(api, resolverAddress , userSeed, agentSeed);
        userIdentity = idSdk.CreateUserIdentity(userKeyName, userKeyID);
        agentIdentity = idSdk.CreateAgentIdentity(agentKeyName, agentKeyID);
        idSdk.UserDelegatesAuthenticationToAgent(agentIdentity, userIdentity, authDelegationID);
    }

    @Override
    public String newAuthenticationToken(Duration expiry) {
        return newAuthenticationToken(expiry, "undefined");
    }

    @Override
    public String newAuthenticationToken(Duration expiry, String audience) {
        return idSdk.CreateAgentAuthToken(this.agentIdentity, this.userIdentity.did(), audience, expiry);
    }

    @Override
    public Identity newTwinIdentity(String twinKeyName, String controlDelegationID) {
        return idSdk.CreateTwinIdentityWithControlDelegation(this.agentIdentity, twinKeyName, controlDelegationID);
    }

    public Identity agentIdentity() {
        return agentIdentity;
    }

    public Identity userIdentity() {
        return userIdentity;
    }

    public static final class Builder {
        private String userSeed;
        private String agentSeed;
        private String userKeyName;
        private String agentKeyName;
        private String userKeyID;
        private String agentKeyID;
        private String authDelegationID;
        private String resolverAddress;

        private Builder() {
            authDelegationID = "#deleg-0";
            userKeyID = "#user-0";
            agentKeyID = "agent-0";
        }

        public static Builder anIdentityManager() {
            return new Builder();
        }

        public Builder withUserSeed(String userSeed) {
            this.userSeed = userSeed;
            return this;
        }

        public Builder withAgentSeed(String agentSeed) {
            this.agentSeed = agentSeed;
            return this;
        }

        public Builder withUserKeyName(String userKeyName) {
            this.userKeyName = userKeyName;
            return this;
        }

        public Builder withUserKeyID(String userKeyID) {
            this.userKeyID = userKeyID;
            return this;
        }

        public Builder withAgentKeyName(String agentKeyName) {
            this.agentKeyName = agentKeyName;
            return this;
        }

        public Builder withAgentKeyID(String agentKeyID) {
            this.agentKeyID = agentKeyID;
            return this;
        }

        public Builder withResolverAddress(String resolverAddress) {
            this.resolverAddress = resolverAddress;
            return this;
        }

        public Builder withAuthDelegationID(String authDelegationID) {
            this.authDelegationID = authDelegationID;
            return this;
        }

        public SimpleIdentityManager build() {
            return new SimpleIdentityManager(
                    resolverAddress,
                    userSeed, agentSeed,
                    userKeyName, userKeyID,
                    agentKeyName, agentKeyID,
                    authDelegationID);
        }
    }
}
