package com.invex.test.authentication.security.client;

import com.invex.test.authentication.configuration.SecurityProperties;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.core.annotation.Order;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.oauth2.server.authorization.settings.OAuth2TokenFormat;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;
import org.springframework.stereotype.Component;

import java.nio.charset.StandardCharsets;
import java.util.UUID;

@Component
@Order(1)
public class RegisteredClientSeeder implements ApplicationRunner {

    private final RegisteredClientRepository clientRepository;
    private final PasswordEncoder passwordEncoder;
    private final SecurityProperties properties;

    public RegisteredClientSeeder(RegisteredClientRepository clientRepository,
                                  PasswordEncoder passwordEncoder,
                                  SecurityProperties properties) {
        this.clientRepository = clientRepository;
        this.passwordEncoder = passwordEncoder;
        this.properties = properties;
    }

    @Override
    public void run(ApplicationArguments arguments) {
        seedMissingClients();
    }

    public void seedMissingClients() {
        SecurityProperties.PublicClient publicClient = properties.getOauth2().getPublicClient();
        SecurityProperties.ServiceClient serviceClient = properties.getOauth2().getServiceClient();
        saveInteractiveClient(publicClient);
        if (clientRepository.findByClientId(serviceClient.getId()) == null) {
            clientRepository.save(serviceClient(serviceClient));
        }
    }

    private void saveInteractiveClient(SecurityProperties.PublicClient publicClient) {
        requireText(publicClient.getId(), "Public client id is required");
        RegisteredClient existing = clientRepository.findByClientId(publicClient.getId());
        if (existing == null) {
            clientRepository.save(interactiveClient(publicClient));
            return;
        }
        RegisteredClient.Builder builder = RegisteredClient.from(existing);
        boolean missingRedirect = false;
        for (String redirectUri : publicClient.getRedirectUris()) {
            if (!existing.getRedirectUris().contains(redirectUri)) {
                builder.redirectUri(redirectUri);
                missingRedirect = true;
            }
        }
        if (missingRedirect) {
            clientRepository.save(builder.build());
        }
    }

    private RegisteredClient interactiveClient(SecurityProperties.PublicClient publicClient) {
        requireText(publicClient.getId(), "Public client id is required");
        if (publicClient.getRedirectUris() == null || publicClient.getRedirectUris().isEmpty()) {
            throw new InvalidClientConfigurationException("Public client redirect URIs are required");
        }
        if (publicClient.getScopes() == null || publicClient.getScopes().isEmpty()) {
            throw new InvalidClientConfigurationException("Public client scopes are required");
        }
        RegisteredClient.Builder builder = RegisteredClient.withId(stableId(publicClient.getId()))
                .clientId(publicClient.getId())
                .clientName(publicClient.getId())
                .clientAuthenticationMethod(ClientAuthenticationMethod.NONE)
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
                .clientSettings(ClientSettings.builder()
                        .requireProofKey(true)
                        .requireAuthorizationConsent(false)
                        .build())
                .tokenSettings(tokenSettings());
        publicClient.getRedirectUris().forEach(builder::redirectUri);
        publicClient.getScopes().forEach(builder::scope);
        return builder.build();
    }

    private RegisteredClient serviceClient(SecurityProperties.ServiceClient serviceClient) {
        requireText(serviceClient.getId(), "Service client id is required");
        requireText(serviceClient.getSecret(), "Service client secret is required");
        if (serviceClient.getScopes() == null || serviceClient.getScopes().isEmpty()) {
            throw new InvalidClientConfigurationException("Service client scopes are required");
        }
        RegisteredClient.Builder builder = RegisteredClient.withId(stableId(serviceClient.getId()))
                .clientId(serviceClient.getId())
                .clientName(serviceClient.getId())
                .clientSecret(passwordEncoder.encode(serviceClient.getSecret()))
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
                .clientSettings(ClientSettings.builder().requireProofKey(false).build())
                .tokenSettings(tokenSettings());
        serviceClient.getScopes().forEach(builder::scope);
        return builder.build();
    }

    private TokenSettings tokenSettings() {
        SecurityProperties.Token token = properties.getToken();
        return TokenSettings.builder()
                .accessTokenFormat(OAuth2TokenFormat.SELF_CONTAINED)
                .accessTokenTimeToLive(token.getAccessTokenTimeToLive())
                .refreshTokenTimeToLive(token.getRefreshTokenTimeToLive())
                .authorizationCodeTimeToLive(token.getAuthorizationCodeTimeToLive())
                .reuseRefreshTokens(false)
                .idTokenSignatureAlgorithm(SignatureAlgorithm.RS256)
                .build();
    }

    static String stableId(String clientId) {
        return UUID.nameUUIDFromBytes(clientId.getBytes(StandardCharsets.UTF_8)).toString();
    }

    private static void requireText(String value, String message) {
        if (value == null || value.isBlank()) {
            throw new InvalidClientConfigurationException(message);
        }
    }
}
