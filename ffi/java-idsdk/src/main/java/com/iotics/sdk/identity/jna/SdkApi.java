package com.iotics.sdk.identity.jna;

import com.iotics.sdk.identity.go.StringResult;
import com.sun.jna.Library;

public interface SdkApi extends Library {

    StringResult CreateDefaultSeed();

    StringResult MnemonicBip39ToSeed(String mnemonics);

    StringResult SeedBip39ToMnemonic(String seed);

    StringResult RecreateAgentIdentity(
            String resolverAddress,
            String keyName,
            String name,
            String seed);

    StringResult RecreateUserIdentity(
            String resolverAddress,
            String keyName,
            String name,
            String seed);

    StringResult CreateAgentIdentity(
            String resolverAddress,
            String keyName,
            String name,
            String seed);

    StringResult CreateUserIdentity(
            String resolverAddress,
            String keyName,
            String name,
            String seed);

    StringResult CreateTwinDidWithControlDelegation(
            String resolverAddress,
            String agentDid,
            String agentKeyName,
            String agentName,
            String agentSeed,
            String twinKeyName,
            String twinName);

    String UserDelegatesAuthenticationToAgent(
            String resolverAddress,

            String agentDid,
            String agentKeyName,
            String agentName,
            String agentSeed,

            String userDid,
            String userKeyName,
            String userName,
            String userSeed,

            String delegationName);

    StringResult IsAllowedFor(
            String resolverAddress,
            String token);

    String TwinDelegatesControlToAgent(
            String resolverAddress,

            String agentDid,
            String agentKeyName,
            String agentName,
            String agentSeed,

            String twinDid,
            String twinKeyName,
            String twinName,
            String twinSeed,

            String delegationName);

    StringResult CreateAgentAuthToken(
            String agentDid,
            String agentKeyName,
            String agentName,
            String agentSeed,

            String userDid,

            String audience,

            long durationInSeconds);


}