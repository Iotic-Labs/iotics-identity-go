package com.iotics.sdk.identity.jna;

import com.sun.jna.Native;

import java.io.File;

public class JnaSdkApiInitialiser {
    private static String LIB_NAME = "lib-iotics-id-sdk.so";
    private static String LIB_PATH = new File("./lib/"+LIB_NAME).getAbsolutePath();

    private SdkApi idProxy;

    public JnaSdkApiInitialiser() {
        try {
            this.idProxy = Native.loadLibrary(LIB_NAME, SdkApi.class);
        } catch(UnsatisfiedLinkError e) {
            this.idProxy = Native.loadLibrary(LIB_PATH, SdkApi.class);
        }
    }

    public JnaSdkApiInitialiser(String libPath) {
        this.idProxy = Native.loadLibrary(libPath, SdkApi.class);
    }

    // not thread safe
    public final SdkApi get() {
        return idProxy;
    }

}
