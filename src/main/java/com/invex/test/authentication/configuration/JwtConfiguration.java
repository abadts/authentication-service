package com.invex.test.authentication.configuration;

import com.invex.test.authentication.security.key.InvalidSigningKeyException;
import com.invex.test.authentication.security.key.RsaKeyMaterial;
import com.invex.test.authentication.security.token.JwtAudienceValidator;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.io.Resource;
import org.springframework.core.io.ResourceLoader;
import org.springframework.security.oauth2.core.DelegatingOAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtValidators;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.util.StreamUtils;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;

@Configuration
@EnableConfigurationProperties(SecurityProperties.class)
public class JwtConfiguration {

    private final ResourceLoader resourceLoader;
    private final RsaKeyMaterial rsaKeyMaterial = new RsaKeyMaterial();

    public JwtConfiguration(ResourceLoader resourceLoader) {
        this.resourceLoader = resourceLoader;
    }

    @Bean
    RSAKey rsaKey(SecurityProperties properties) {
        SecurityProperties.Jwt jwt = properties.getJwt();
        String privateKey = readKey(jwt.getPrivateKey(), jwt.getPrivateKeyLocation(), "RSA private key");
        String publicKey = readKey(jwt.getPublicKey(), jwt.getPublicKeyLocation(), "RSA public key");
        return rsaKeyMaterial.load(privateKey, publicKey);
    }

    @Bean
    JWKSource<SecurityContext> jwkSource(RSAKey rsaKey) {
        JWKSet jwkSet = new JWKSet(rsaKey);
        return (jwkSelector, securityContext) -> jwkSelector.select(jwkSet);
    }

    @Bean
    JwtDecoder jwtDecoder(RSAKey rsaKey, SecurityProperties properties) throws Exception {
        NimbusJwtDecoder decoder = NimbusJwtDecoder.withPublicKey(rsaKey.toRSAPublicKey()).build();
        OAuth2TokenValidator<Jwt> issuerAndTimestamp = JwtValidators.createDefaultWithIssuer(properties.getOauth2().getIssuer());
        decoder.setJwtValidator(new DelegatingOAuth2TokenValidator<>(
                issuerAndTimestamp,
                new JwtAudienceValidator(properties.getJwt().getAudience())
        ));
        return decoder;
    }

    private String readKey(String inlinePem, String location, String keyName) {
        if (inlinePem != null && !inlinePem.isBlank()) {
            return inlinePem;
        }
        if (location == null || location.isBlank()) {
            throw new InvalidSigningKeyException(keyName + " is not configured");
        }
        Resource resource = resourceLoader.getResource(location);
        try (InputStream inputStream = resource.getInputStream()) {
            return StreamUtils.copyToString(inputStream, StandardCharsets.UTF_8);
        } catch (IOException exception) {
            throw new InvalidSigningKeyException(keyName + " could not be read from " + location, exception);
        }
    }
}
