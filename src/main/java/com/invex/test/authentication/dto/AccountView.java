package com.invex.test.authentication.dto;

public record AccountView(String username, String email, String role, boolean enabled) {
}
