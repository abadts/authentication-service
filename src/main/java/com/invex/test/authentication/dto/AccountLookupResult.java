package com.invex.test.authentication.dto;

public record AccountLookupResult(String username, String email, boolean usernameExists, boolean emailExists) {
}
