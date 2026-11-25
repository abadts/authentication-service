package com.invex.test.authentication.dto;

public record AccountBatchResult(String username, String email, String status, String reason) {
}
