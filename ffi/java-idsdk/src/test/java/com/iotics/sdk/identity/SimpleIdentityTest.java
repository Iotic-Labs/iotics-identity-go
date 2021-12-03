package com.iotics.sdk.identity;

import com.iotics.sdk.identity.jna.SdkApi;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.time.Duration;

import static com.iotics.sdk.identity.DataFactory.*;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
public class SimpleIdentityTest {

    @Mock
    SdkApi sdkApi;

    @Test
    void validApiConstruction() {
        assertThrows(NullPointerException.class, () -> {
            new SimpleIdentity(null, "");
        });
        assertThrows(IllegalArgumentException.class, () -> {
            new SimpleIdentity(sdkApi, "invalid url", "some seed");
        });
    }

    @Test
    void whenConstructedWithoutSeed_thenGeneratesNewOne() {
        when(sdkApi.CreateDefaultSeed()).thenReturn(validResult("some seed"));
        new SimpleIdentity(sdkApi, validUrl());

        verify(sdkApi).CreateDefaultSeed();
    }

    @Test
    void whenConstructedWithOneSeed_thenUsesItForBothAgentAndUser() {
        SimpleIdentity si = new SimpleIdentity(sdkApi, validUrl(), "some seed");

        assertEquals("some seed", si.getAgentSeed());
        assertEquals("some seed", si.getUserSeed());

        verifyNoInteractions(sdkApi);
    }

    @Test
    void whenConstructedWithTwoSeed_thenUsesOneForUserAndOneForAgent() {
        SimpleIdentity si = new SimpleIdentity(sdkApi, validUrl(), "user seed", "agent seed");

        assertEquals("agent seed", si.getAgentSeed());
        assertEquals("user seed", si.getUserSeed());

        verifyNoInteractions(sdkApi);
    }

    @Test
    void whenCreateTwinDidWithControlDelegation_thenMapsParametersAndDelegatesToApi() {
        String res = validUrl();

        SimpleIdentity si = new SimpleIdentity(sdkApi, res, "some seed");
        Identity id = aValidAgentIdentity();
        when(sdkApi.CreateTwinDidWithControlDelegation(any(), any(), any(), any(), any(), any(), any())).thenReturn(validResult("twin did"));

        Identity twinId = si.CreateTwinIdentityWithControlDelegation(id, "twinKeyName", "twinName");

        assertEquals(twinId.did(), "twin did");
        assertEquals(twinId.keyName(), "twinKeyName");
        assertEquals(twinId.name(), "twinName");
        verify(sdkApi).CreateTwinDidWithControlDelegation(res, id.did(), id.keyName(), id.name(), si.getAgentSeed(), "twinKeyName", "twinName");
    }

    @Test
    void whenCreateAgentIdentity_thenMapsParametersAndDelegatesToApi() {
        String res = validUrl();

        SimpleIdentity si = new SimpleIdentity(sdkApi, res, "some seed");
        when(sdkApi.CreateAgentIdentity(any(), any(), any(), any())).thenReturn(validResult("agent did"));

        Identity agentIdentity = si.CreateAgentIdentity("agentKeyName", "agentName");

        assertEquals(agentIdentity.did(), "agent did");
        assertEquals(agentIdentity.keyName(), "agentKeyName");
        assertEquals(agentIdentity.name(), "agentName");
        verify(sdkApi).CreateAgentIdentity(res,  "agentKeyName",  "agentName", "some seed");
    }

    @Test
    void whenCreateUserIdentity_thenMapsParametersAndDelegatesToApi() {
        String res = validUrl();

        SimpleIdentity si = new SimpleIdentity(sdkApi, res, "some seed");
        when(sdkApi.CreateUserIdentity(any(), any(), any(), any())).thenReturn(validResult("user did"));

        Identity userIdentity = si.CreateUserIdentity("userKeyName", "userName");

        assertEquals(userIdentity.did(), "user did");
        assertEquals(userIdentity.keyName(), "userKeyName");
        assertEquals(userIdentity.name(), "userName");
        verify(sdkApi).CreateUserIdentity(res,  "userKeyName",  "userName", "some seed");
    }

    @Test
    void whenCreateUserIdentityFails_thenThrows() {
        SimpleIdentity si = new SimpleIdentity(sdkApi, validUrl(), "some seed");
        when(sdkApi.CreateUserIdentity(any(), any(), any(), any())).thenReturn(errorResult("some error"));

        assertThrows(SimpleIdentityException.class, () -> {
            si.CreateUserIdentity("userKeyName", "userName");
        });
    }

    @Test
    void whenCreateAgentAuthToken_thenMapsParametersAndDelegatesToApi() {
        String res = validUrl();

        SimpleIdentity si = new SimpleIdentity(sdkApi, res, "some seed");
        when(sdkApi.CreateAgentAuthToken(any(), any(), any(), any(), any(), anyInt())).thenReturn(validResult("some token"));

        Identity i = aValidAgentIdentity();
        String token = si.CreateAgentAuthToken(i, "did:iotics:user", Duration.ofSeconds(123));

        assertEquals(token, "some token");
        verify(sdkApi).CreateAgentAuthToken(i.did(), i.keyName(),  i.name(), si.getAgentSeed(), "did:iotics:user", Integer.valueOf(123));
    }

    @Test
    void whenUserDelegatesAuthenticationToAgent_thenMapsParametersAndDelegatesToApi() {
        String res = validUrl();
        String as = "agentSeed";
        String us = "userSeed";
        SimpleIdentity si = new SimpleIdentity(sdkApi, res, us, as);

        Identity i = aValidAgentIdentity();
        Identity u = aValidUserIdentity();
        si.UserDelegatesAuthenticationToAgent(i, u, "#foobar");

        verify(sdkApi).UserDelegatesAuthenticationToAgent(res,
                i.did(), i.keyName(),  i.name(), si.getAgentSeed(),
                u.did(), u.keyName(),  u.name(), si.getUserSeed(),
                "#foobar");
    }

    @Test
    void whenTwinDelegatesControlToAgent_thenMapsParametersAndDelegatesToApi() {
        String res = validUrl();
        String as = "agentSeed";
        String us = "userSeed";
        SimpleIdentity si = new SimpleIdentity(sdkApi, res, us, as);

        Identity i = aValidAgentIdentity();
        Identity u = aValidUserIdentity();
        si.TwinDelegatesControlToAgent(i, u, "#foobar");

        verify(sdkApi).TwinDelegatesControlToAgent(res,
                i.did(), i.keyName(),  i.name(), si.getAgentSeed(),
                u.did(), u.keyName(),  u.name(), si.getAgentSeed(),
                "#foobar");
    }

}
