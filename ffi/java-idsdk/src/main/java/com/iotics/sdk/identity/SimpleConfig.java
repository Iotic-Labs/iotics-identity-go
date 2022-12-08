package com.iotics.sdk.identity;

import com.google.common.io.Files;
import com.google.gson.Gson;

import java.io.FileNotFoundException;
import java.io.Reader;
import java.nio.charset.Charset;
import java.nio.file.Path;
import java.nio.file.Paths;

public class SimpleConfig {

    private String seed;
    private String keyName;

    private static SimpleConfig readConf(Path p) throws FileNotFoundException {
        Gson gson = new Gson();
        Reader reader = Files.newReader(p.toFile(), Charset.forName("UTF-8"));
        return gson.fromJson(reader, SimpleConfig.class);
    }

    private static SimpleConfig readConfFromHome(String name) throws FileNotFoundException {
        Path p = Paths.get(System.getProperty("user.home"), ".config", "iotics", name);
        return readConf(p);
    }

    public String seed() {
        return seed;
    }

    public String keyName() {
        return keyName;
    }
}
