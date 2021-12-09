package com.iotics.sdk.identity;

import java.util.Objects;

public final class Identity {

    private final String name;
    private final String keyName;
    private final String did;

    public Identity(String keyName, String name, String did) {
        Objects.requireNonNull(name);
        Objects.requireNonNull(keyName);
        Objects.requireNonNull(did);
        this.name = name;
        this.keyName = keyName;
        this.did = did;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        Identity identity = (Identity) o;
        return Objects.equals(name, identity.name) && Objects.equals(keyName, identity.keyName) && Objects.equals(did, identity.did);
    }

    @Override
    public int hashCode() {
        return Objects.hash(name, keyName, did);
    }

    @Override
    public String toString() {
        return "Identity{" +
                "name='" + name + '\'' +
                ", keyName='" + keyName + '\'' +
                ", did='" + did + '\'' +
                '}';
    }

    public String name() {
        return name;
    }

    public String keyName() {
        return keyName;
    }

    public String did() {
        return did;
    }
}