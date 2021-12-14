package com.iotics.sdk.identity.jna;

import com.sun.jna.Native;

import java.io.File;

public class JnaSdkApiInitialiser {
    private static String LIB_PATH = new File("./lib/lib-iotics-id-sdk.so").getAbsolutePath();
    private final String libPath;

    private final SdkApi idProxy;

    public JnaSdkApiInitialiser() {
        this(LIB_PATH);
    }

    public JnaSdkApiInitialiser(String libPath) {
        this.libPath = libPath;
        this.idProxy = Native.loadLibrary(this.libPath, SdkApi.class);
    }

    // not thread safe
    public final SdkApi get() {
        return idProxy;
    }

}
