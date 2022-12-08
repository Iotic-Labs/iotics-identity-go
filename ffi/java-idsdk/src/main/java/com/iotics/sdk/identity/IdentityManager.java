package com.iotics.sdk.identity;

import java.time.Duration;

/**
 * However agents and users identities are created, at runtime, only new tokens and new twin identities must be created.
 * This interface provides these methods for applications to simply  manage their own identity affairs.
 */
public interface IdentityManager {
    String newAuthenticationToken(Duration expiry);

    Identity newTwinIdentity(String twinKeyName, String controlDelegationID);

    default Identity newTwinIdentity(String twinKeyName) {
        return newTwinIdentity(twinKeyName, "#c-delegation-0");
    }
}
