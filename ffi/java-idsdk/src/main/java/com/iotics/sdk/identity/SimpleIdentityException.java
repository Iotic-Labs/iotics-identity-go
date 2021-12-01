package com.iotics.sdk.identity;

public class SimpleIdentityException extends RuntimeException {
    public SimpleIdentityException(String message) {
        super(message);
    }

    public SimpleIdentityException(String message, Throwable cause) {
        super(message, cause);
    }
}
