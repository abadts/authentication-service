package com.invex.test.authentication.controller;

import com.invex.test.authentication.service.UserAccountService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.security.SecurityRequirements;
import io.swagger.v3.oas.annotations.tags.Tag;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

@RestController
@RequestMapping("/api/v1/security")
@Tag(name = "Identity")
public class SecurityController {

    private final UserAccountService userAccountService;

    public SecurityController(UserAccountService userAccountService) {
        this.userAccountService = userAccountService;
    }

    @GetMapping("/health")
    @SecurityRequirements
    @Operation(summary = "Service status")
    public ServiceHealth health() {
        return new ServiceHealth("UP", "authentication-service");
    }

    @GetMapping("/me")
    @Operation(summary = "Own email of the authenticated user")
    public CurrentUserResponse currentUser(Authentication authentication) {
        Jwt accessToken = (Jwt) authentication.getPrincipal();
        List<String> authorities = authentication.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .sorted()
                .toList();
        String email = userAccountService.emailOf(accessToken.getSubject()).orElse(null);
        return new CurrentUserResponse(accessToken.getSubject(), email, authorities);
    }

    public record ServiceHealth(String status, String service) {
    }

    public record CurrentUserResponse(String subject, String email, List<String> authorities) {
    }
}
