package com.iotics.sdk.identity.experimental;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonObject;

import java.text.SimpleDateFormat;
import java.util.Base64;
import java.util.Date;
import java.util.TimeZone;

public class JWT {
    private final String header;
    private final String signature;
    private final String payload;
    private final String token;

    public JWT(String token) {
        this.token = token;
        String[] chunks = token.split("\\.");
        Base64.Decoder decoder = Base64.getDecoder();

        try {
            this.header = new String(decoder.decode(chunks[0]));
            this.payload = new String(decoder.decode(chunks[1]));
            this.signature = chunks[2];
        } catch (ArrayIndexOutOfBoundsException e) {
            throw new IllegalArgumentException("Invalid JWT token");
        }
    }

    public String toNiceString() {
        Gson gson = new GsonBuilder()
                .setPrettyPrinting()
                .create();
        JsonObject h = gson.fromJson(this.header, JsonObject.class);

        try {
            JsonObject p = gson.fromJson(this.payload, JsonObject.class);
            long exp = p.get("exp").getAsLong();
            long iat = p.get("iat").getAsLong();

            SimpleDateFormat simpleDateFormat = new SimpleDateFormat("yyyy-MMM-dd HH:mm:ss");
            simpleDateFormat.setTimeZone(TimeZone.getTimeZone("UTC"));

            String sExp = simpleDateFormat.format(new Date(exp * 1000));
            String sIat = simpleDateFormat.format(new Date(iat * 1000));
            p.remove("exp");
            p.remove("iat");
            p.addProperty("exp", sExp);
            p.addProperty("iat", sIat);

            JsonObject obj = gson.fromJson("{}", JsonObject.class);
            obj.add("header", h);
            obj.add("payload", p);
            obj.addProperty("signature", this.signature);
            return obj.toString();
        } catch (Exception e) {
            throw new RuntimeException("Invalid token", e);
        }
    }

    @Override
    public String toString() {
        return "JWT{" +
                "header='" + header + '\'' +
                ", payload='" + payload + '\'' +
                ", signature='" + signature + '\'' +
                '}';
    }
}
