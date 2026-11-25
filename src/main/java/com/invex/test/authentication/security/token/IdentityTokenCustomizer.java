package com.invex.test.authentication.security.token;

import com.invex.test.authentication.configuration.SecurityProperties;
import com.invex.test.authentication.domain.model.Role;
import com.invex.test.authentication.domain.model.AuthenticationUser;
import com.invex.test.authentication.repository.AuthenticationUserRepository;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.oidc.StandardClaimNames;
import org.springframework.security.oauth2.core.oidc.endpoint.OidcParameterNames;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

@Component
public class IdentityTokenCustomizer implements OAuth2TokenCustomizer<JwtEncodingContext> {

    static final String ROLES = "roles";

    private final AuthenticationUserRepository userRepository;
    private final List<String> audiences;

    public IdentityTokenCustomizer(AuthenticationUserRepository userRepository, SecurityProperties properties) {
        this.userRepository = userRepository;
        this.audiences = resourceAudiences(properties);
    }

    @Override
    public void customize(JwtEncodingContext context) {
        if (OAuth2TokenType.ACCESS_TOKEN.equals(context.getTokenType())) {
            context.getClaims().audience(new ArrayList<>(audiences));
            authenticatedUser(context).ifPresent(user -> addAccessTokenClaims(context, user));
            return;
        }
        if (OidcParameterNames.ID_TOKEN.equals(context.getTokenType().getValue())) {
            authenticatedUser(context).ifPresent(user -> addIdentityClaims(context, user));
        }
    }

    private void addAccessTokenClaims(JwtEncodingContext context, AuthenticationUser user) {
        List<String> roles = new ArrayList<>(user.getRoles().stream()
                .map(Role::getCode)
                .distinct()
                .sorted()
                .toList());
        context.getClaims().claim(ROLES, roles);
    }

    private static void addIdentityClaims(JwtEncodingContext context, AuthenticationUser user) {
        context.getClaims().claim(StandardClaimNames.EMAIL, user.getEmail());
        context.getClaims().claim(StandardClaimNames.PREFERRED_USERNAME, user.getUsername());
    }

    private static List<String> resourceAudiences(SecurityProperties properties) {
        List<String> configured = properties.getJwt().getResourceAudiences();
        if (configured == null || configured.isEmpty()) {
            return List.of(properties.getJwt().getAudience());
        }
        return List.copyOf(configured);
    }

    private Optional<AuthenticationUser> authenticatedUser(JwtEncodingContext context) {
        Authentication principal = context.getPrincipal();
        if (principal == null || principal.getName() == null || principal.getName().isBlank()) {
            return Optional.empty();
        }
        return userRepository.findByUsername(principal.getName());
    }
}
