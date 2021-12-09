package com.iotics.sdk.identity;

import com.iotics.sdk.identity.jna.SdkApi;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import static com.iotics.sdk.identity.DataFactory.validResult;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
public class SeedsTest {
    @Mock
    SdkApi sdkApi;

    @Test
    void whenCreatingDefaultSeed_thenDelegatesToApi() {
        when(sdkApi.CreateDefaultSeed()).thenReturn(validResult("some seed"));
        new Seeds(sdkApi).CreateDefaultSeed();
        verify(sdkApi).CreateDefaultSeed();
    }

    @Test
    void whenMnemonicBip39ToSeed_thenDelegatesToApi() {
        when(sdkApi.MnemonicBip39ToSeed(any())).thenReturn(validResult("some seed"));
        new Seeds(sdkApi).MnemonicBip39ToSeed ("1 2 3");
        verify(sdkApi).MnemonicBip39ToSeed("1 2 3");
    }

    @Test
    void whenSeedBip39ToMnemonic_thenDelegatesToApi() {
        when(sdkApi.SeedBip39ToMnemonic(any())).thenReturn(validResult("1 2 3"));
        new Seeds(sdkApi).SeedBip39ToMnemonic("some seed");
        verify(sdkApi).SeedBip39ToMnemonic("some seed");
    }

}
