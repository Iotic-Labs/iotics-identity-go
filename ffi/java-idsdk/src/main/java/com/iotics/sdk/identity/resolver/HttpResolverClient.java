package com.iotics.sdk.identity.resolver;

import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.Response;
import okhttp3.ResponseBody;

import java.io.IOException;
import java.net.MalformedURLException;
import java.net.URI;
import java.net.URL;
import java.util.Base64;

public final class HttpResolverClient implements ResolverClient {
    private final URL base;
    private final OkHttpClient client;

    public HttpResolverClient(URL base) {
        this.base = base;
        this.client = new OkHttpClient();
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
            ResponseBody body = response.body();
            if(response.code() > 299) {
                if(response.code() == 404) {
                    return new Result("DID not found", "application/text", true);
                }
                if(body != null) {
                    return new Result(body.string(), "application/xml", true);
                }
                else {
                    return new Result("No result found", "application/text", true);
                }
            }
            if(body == null) {
                return new Result("invalid response", "application/text", true);
            }
            String bodyString = body.string();
            String[] parts = bodyString.split("\"");
            String token = parts[3];
            Base64.Decoder decoder = Base64.getDecoder();
            String payload = new String(decoder.decode(token.split("\\.")[1]));
            return new Result(payload, "application/json", false);
        }

    }

    public static void main(String[] args) throws Exception {
        HttpResolverClient c = new HttpResolverClient(URI.create("https://did.stg.iotics.com").toURL());
        Result agent = c.discover("did:iotics:iotJxn2AHBkaFXKkBymbFYcVokGhLShLtUf1");
        Result user = c.discover("did:iotics:iotLUmwHDFtpfLEWTeGAQwyp4Y5FoSTt4jbg");

        System.out.println("AGENT ------");
        System.out.println(agent);
        System.out.println("USER ------");
        System.out.println(user);
    }
}
