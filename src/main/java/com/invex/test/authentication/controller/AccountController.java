package com.invex.test.authentication.controller;

import com.invex.test.authentication.dto.AccountBatchReport;
import com.invex.test.authentication.dto.AccountDraft;
import com.invex.test.authentication.dto.AccountLookup;
import com.invex.test.authentication.dto.AccountLookupReport;
import com.invex.test.authentication.dto.AccountView;
import com.invex.test.authentication.service.UserAccountService;
import com.invex.test.authentication.security.AuthorizationCodes;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.ExampleObject;
import io.swagger.v3.oas.annotations.parameters.RequestBody;
import io.swagger.v3.oas.annotations.tags.Tag;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

@RestController
@RequestMapping("/api/v1/security/accounts")
@Tag(name = "Accounts")
public class AccountController {

    private final UserAccountService userAccountService;

    public AccountController(UserAccountService userAccountService) {
        this.userAccountService = userAccountService;
    }

    @PostMapping
    @PreAuthorize("hasRole('" + AuthorizationCodes.ADMINISTRATOR + "')")
    @Operation(summary = "Open an EMPLOYEE account. Only an administrator can call this.")
    @RequestBody(content = @Content(mediaType = "application/json", examples = {
            @ExampleObject(
                    name = "karla.chavez",
                    value = "{\"username\":\"karla.chavez\",\"password\":\"ChangeMe123!\",\"email\":\"karla.chavez@test.invex.local\",\"role\":\"EMPLOYEE\"}"
            ),
            @ExampleObject(
                    name = "juan.perez",
                    value = "{\"username\":\"juan.perez\",\"password\":\"ChangeMe123!\",\"email\":\"juan.perez@test.invex.local\",\"role\":\"EMPLOYEE\"}"
            )
    }))
    public ResponseEntity<AccountView> open(@org.springframework.web.bind.annotation.RequestBody AccountRequest request) {
        AccountView account = userAccountService.openAccount(
                request.username(),
                request.password(),
                request.email(),
                request.role()
        );
        return ResponseEntity.status(HttpStatus.CREATED).body(account);
    }

    @PostMapping("/validate")
    @PreAuthorize("hasRole('" + AuthorizationCodes.ADMINISTRATOR + "')")
    @Operation(summary = "Check whether usernames or emails already exist. Only an administrator can call this.")
    @RequestBody(content = @Content(mediaType = "application/json", examples = {
            @ExampleObject(
                    name = "karla.chavez and juan.perez",
                    value = "{\"accounts\":[{\"username\":\"karla.chavez\",\"email\":\"karla.chavez@test.invex.local\"},{\"username\":\"juan.perez\",\"email\":\"juan.perez@test.invex.local\"}]}"
            )
    }))
    public AccountLookupReport validate(@org.springframework.web.bind.annotation.RequestBody AccountValidationRequest request) {
        return userAccountService.validateAccounts(request.accounts());
    }

    @PostMapping("/batch")
    @PreAuthorize("hasRole('" + AuthorizationCodes.ADMINISTRATOR + "')")
    @Operation(summary = "Open several EMPLOYEE accounts. Only an administrator can call this.")
    @RequestBody(content = @Content(mediaType = "application/json", examples = {
            @ExampleObject(
                    name = "karla.chavez and juan.perez",
                    value = "{\"accounts\":[{\"username\":\"karla.chavez\",\"password\":\"ChangeMe123!\",\"email\":\"karla.chavez@test.invex.local\"},{\"username\":\"juan.perez\",\"password\":\"ChangeMe123!\",\"email\":\"juan.perez@test.invex.local\"}]}"
            )
    }))
    public AccountBatchReport createBatch(@org.springframework.web.bind.annotation.RequestBody AccountBatchRequest request) {
        return userAccountService.createAccounts(request.accounts());
    }

    @DeleteMapping("/{username}")
    @PreAuthorize("hasRole('" + AuthorizationCodes.ADMINISTRATOR + "')")
    @Operation(summary = "Delete an account. Only an administrator can call this.")
    public ResponseEntity<Void> delete(@PathVariable String username) {
        userAccountService.deleteAccount(username);
        return ResponseEntity.noContent().build();
    }

    public record AccountRequest(String username, String password, String email, String role) {
    }

    public record AccountBatchRequest(List<AccountDraft> accounts) {
    }

    public record AccountValidationRequest(List<AccountLookup> accounts) {
    }
}
