package com.invex.test.authentication.dto;

import java.util.List;

public record AccountLookupReport(List<AccountLookupResult> results) {
}
