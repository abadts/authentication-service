package com.invex.test.authentication.service;

public class AccountRoleNotAllowedException extends RuntimeException {

    public AccountRoleNotAllowedException(String message) {
        super(message);
    }
}
