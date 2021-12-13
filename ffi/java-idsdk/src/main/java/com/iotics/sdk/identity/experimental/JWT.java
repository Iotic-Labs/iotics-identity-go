package com.iotics.sdk.identity.experimental;

import org.json.JSONObject;

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
        JSONObject h = new JSONObject(this.header);

        try {
            JSONObject p = new JSONObject(this.payload);
            long exp = p.getLong("exp");
            long iat = p.getLong("iat");

            SimpleDateFormat simpleDateFormat = new SimpleDateFormat("yyyy-MMM-dd HH:mm:ss");
            simpleDateFormat.setTimeZone(TimeZone.getTimeZone("UTC"));

            String sExp = simpleDateFormat.format(new Date(exp * 1000));
            String sIat = simpleDateFormat.format(new Date(iat * 1000));
            p.put("exp", sExp).put("iat", sIat);

            JSONObject obj = new JSONObject();
            obj.put("header", h).put("payload", p).put("signature", this.signature);
            return obj.toString(2);
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
