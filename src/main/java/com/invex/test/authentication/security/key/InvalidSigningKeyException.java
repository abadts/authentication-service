package com.invex.test.authentication.security.key;

public class InvalidSigningKeyException extends RuntimeException {

    public InvalidSigningKeyException(String message) {
        super(message);
    }

    public InvalidSigningKeyException(String message, Throwable cause) {
        super(message, cause);
    }
}
