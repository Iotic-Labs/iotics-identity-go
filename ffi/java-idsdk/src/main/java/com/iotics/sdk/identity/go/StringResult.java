package com.iotics.sdk.identity.go;

import com.sun.jna.Pointer;
import com.sun.jna.Structure;

import java.util.Arrays;
import java.util.List;

public class StringResult extends Structure implements Structure.ByValue {
    // need to be public for jra to work
    public String value;
    public String err;

    // needed for jra to instantiate this class
    public StringResult() {
    }

    public StringResult(String value, String err) {
        this.value = value;
        this.err = err;
    }

    protected List<String> getFieldOrder() {
        return Arrays.asList("value", "err");
    }

    @Override
    public String toString() {
        return "StringResult{" +
                "value='" + value + '\'' +
                ", r1='" + err + '\'' +
                '}';
    }
}