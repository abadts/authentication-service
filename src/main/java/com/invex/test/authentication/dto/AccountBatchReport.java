package com.invex.test.authentication.dto;

import java.util.List;

public record AccountBatchReport(List<AccountBatchResult> results) {
}
