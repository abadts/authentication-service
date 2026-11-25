package com.invex.test.authentication.controller;

import com.invex.test.authentication.service.AccountNotFoundException;
import com.invex.test.authentication.service.AccountRoleNotAllowedException;
import com.invex.test.authentication.service.DuplicateAccountException;
import com.invex.test.authentication.service.InvalidAccountDataException;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.DisabledException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

@RestControllerAdvice
public class SecurityExceptionHandler {

    @ExceptionHandler({BadCredentialsException.class, DisabledException.class})
    ResponseEntity<ApiError> unauthorized() {
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(new ApiError("Invalid credentials"));
    }

    @ExceptionHandler(InvalidAccountDataException.class)
    ResponseEntity<ApiError> invalidAccount(InvalidAccountDataException exception) {
        return ResponseEntity.badRequest().body(new ApiError(exception.getMessage()));
    }

    @ExceptionHandler(DuplicateAccountException.class)
    ResponseEntity<ApiError> duplicateAccount(DuplicateAccountException exception) {
        return ResponseEntity.status(HttpStatus.CONFLICT).body(new ApiError(exception.getMessage()));
    }

    @ExceptionHandler(AccountNotFoundException.class)
    ResponseEntity<ApiError> accountNotFound(AccountNotFoundException exception) {
        return ResponseEntity.status(HttpStatus.NOT_FOUND).body(new ApiError(exception.getMessage()));
    }

    @ExceptionHandler(AccountRoleNotAllowedException.class)
    ResponseEntity<ApiError> roleNotAllowed(AccountRoleNotAllowedException exception) {
        return ResponseEntity.status(HttpStatus.FORBIDDEN).body(new ApiError(exception.getMessage()));
    }

    public record ApiError(String message) {
    }
}
