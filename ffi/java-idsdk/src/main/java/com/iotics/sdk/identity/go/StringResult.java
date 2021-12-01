package com.iotics.sdk.identity.go;

import com.sun.jna.Pointer;
import com.sun.jna.Structure;

import java.util.Arrays;
import java.util.List;

public class StringResult extends Structure implements Structure.ByValue {
    public String value;
    public String err;

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