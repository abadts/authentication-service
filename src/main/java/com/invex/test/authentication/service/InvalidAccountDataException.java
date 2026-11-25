package com.invex.test.authentication.service;

public class InvalidAccountDataException extends RuntimeException {

    public InvalidAccountDataException(String message) {
        super(message);
    }
}
