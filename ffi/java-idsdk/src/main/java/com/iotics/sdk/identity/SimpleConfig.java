package com.iotics.sdk.identity;

import com.google.common.base.Strings;
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

    public static SimpleConfig fromEnv(String prefix) {
        SimpleConfig sc = new SimpleConfig();
        sc.seed = System.getenv(prefix + "SEED");
        sc.keyName = System.getenv(prefix + "KEYNAME");
        return sc;
    }

    public static SimpleConfig readConf(Path p) throws FileNotFoundException {
        Gson gson = new Gson();
        Reader reader = Files.newReader(p.toFile(), Charset.forName("UTF-8"));
        return gson.fromJson(reader, SimpleConfig.class);
    }
    public static SimpleConfig readConf(String path, SimpleConfig def) {
        if (path == null){
            if(def == null) {
                throw new IllegalArgumentException("null default");
            }
            return def;
        }
        return SimpleConfig.readConf(Path.of(path), def);
    }

    public static SimpleConfig readConf(Path p, SimpleConfig def) {
        try {
            Gson gson = new Gson();
            Reader reader = Files.newReader(p.toFile(), Charset.forName("UTF-8"));
            SimpleConfig sc = gson.fromJson(reader, SimpleConfig.class);
            if(sc == null) {
                if(def == null) {
                    throw new IllegalArgumentException("null default");
                }
                return def;
            }
            return sc.cloneWithDefaults(def);
        } catch (FileNotFoundException e) {
            if(def == null) {
                throw new IllegalArgumentException("null default");
            }
            return def;
        }
    }

    public static SimpleConfig readConfFromHome(String name) throws FileNotFoundException {
        Path p = Paths.get(System.getProperty("user.home"), ".config", "iotics", name);
        return readConf(p);
    }

    public SimpleConfig(String seed, String keyName) {
        this.seed = seed;
        this.keyName = keyName;
    }

    public String seed() {
        return seed;
    }

    public String keyName() {
        return keyName;
    }

    public boolean isValid() {
        return !Strings.isNullOrEmpty(this.seed) && !Strings.isNullOrEmpty(this.keyName) ;
    }

    private SimpleConfig cloneWithDefaults(SimpleConfig def) {
        SimpleConfig sc = new SimpleConfig();
        sc.seed = this.seed;
        if(sc.seed == null) {
            sc.seed = def.seed;
        }
        sc.keyName = this.keyName;
        if(sc.keyName == null) {
            sc.keyName = def.keyName;
        }
        return sc;
    }
}
