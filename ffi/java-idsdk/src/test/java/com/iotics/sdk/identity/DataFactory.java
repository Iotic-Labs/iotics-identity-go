package com.iotics.sdk.identity;

import com.iotics.sdk.identity.go.StringResult;

public final class DataFactory {
    public static String validUrl() {
        return "http://localhost:2020";
    }

    public static StringResult validResult(String value) {
        return new StringResult(value, null);
    }

    public static StringResult errorResult(String err) {
        return new StringResult(null, err);
    }

    public static Identity aValidAgentIdentity() {
        return new Identity("aKeyName", "aName", "did:iotics:123");
    }

    public static Identity aValidUserIdentity() {
        return new Identity("uKeyName", "uName", "did:iotics:abc");
    }

}
