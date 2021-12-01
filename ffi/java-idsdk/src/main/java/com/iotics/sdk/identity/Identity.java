package com.iotics.sdk.identity;

import java.util.Objects;

public record Identity(String keyName, String name, String did) {
    public Identity {
        Objects.requireNonNull(name);
        Objects.requireNonNull(keyName);
        Objects.requireNonNull(did);
    }
}