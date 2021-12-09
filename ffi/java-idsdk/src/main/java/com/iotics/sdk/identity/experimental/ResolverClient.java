package com.iotics.sdk.identity.experimental;

import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.Response;
import org.json.JSONObject;

import java.io.IOException;
import java.net.MalformedURLException;
import java.net.URI;
import java.net.URL;
import java.util.Base64;
import java.util.Objects;

public class ResolverClient {
    private final URL base;
    private final int DEFAULT_TIMEOUT = 2000;
    private final OkHttpClient client;

    public ResolverClient(URL base) {
        this.base = base;
        this.client = new OkHttpClient();
    }

    public final class Result {
        private final String content;
        private final String contentType;
        private final boolean isErr;

        public Result(String content, String contentType, boolean isErr) {
            this.content = content;
            this.contentType = contentType;
            this.isErr = isErr;
        }

        @Override
        public String toString() {
            return "Result{" +
                    "content='" + content + '\'' +
                    ", contentType='" + contentType + '\'' +
                    ", isErr=" + isErr +
                    '}';
        }

        @Override
        public boolean equals(Object o) {
            if (this == o) return true;
            if (o == null || getClass() != o.getClass()) return false;
            Result result = (Result) o;
            return isErr == result.isErr && Objects.equals(content, result.content) && Objects.equals(contentType, result.contentType);
        }

        @Override
        public int hashCode() {
            return Objects.hash(content, contentType, isErr);
        }

        public String content() {
            return content;
        }

        public String contentType() {
            return contentType;
        }

        public boolean isErr() {
            return isErr;
        }
    }

    public Result discover(String did) throws IOException {
        URL url = null;
        try {
            url = new URL(base, "/1.0/discover/" + did);
        } catch (MalformedURLException e) {
            throw new IllegalArgumentException("invalid did");
        }
        Request request = new Request.Builder()
                .url(url)
                .get()
                .build();
        try (Response response = client.newCall(request).execute()) {
            if(response.code() > 299) {
                if(response.code() == 404) {
                    return new Result("DID not found", "application/text", true);
                }
                return new Result(response.body().string(), "application/xml", true);
            }
            JSONObject obj = new JSONObject(response.body().string());
            String token = obj.getString("token");
            Base64.Decoder decoder = Base64.getDecoder();
            String payload = new String(decoder.decode(token.split("\\.")[1]));
            obj = new JSONObject(payload);
            return new Result(obj.toString(3), "application/json", false);
        }

    }

    public static void main(String[] args) throws Exception {
        ResolverClient c = new ResolverClient(URI.create("https://did.stg.iotics.com").toURL());
        Result agent = c.discover("did:iotics:iotJxn2AHBkaFXKkBymbFYcVokGhLShLtUf1");
        Result user = c.discover("did:iotics:iotLUmwHDFtpfLEWTeGAQwyp4Y5FoSTt4jbg");

        System.out.println("AGENT ------");
        System.out.println(agent);
        System.out.println("USER ------");
        System.out.println(user);
    }
}
