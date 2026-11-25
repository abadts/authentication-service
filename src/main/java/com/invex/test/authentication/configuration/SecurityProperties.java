package com.invex.test.authentication.configuration;

import org.springframework.boot.context.properties.ConfigurationProperties;

import java.time.Duration;
import java.util.ArrayList;
import java.util.List;

@ConfigurationProperties(prefix = "security")
public class SecurityProperties {

    private final Oauth2 oauth2 = new Oauth2();
    private final Jwt jwt = new Jwt();
    private final Token token = new Token();
    private final Bootstrap bootstrap = new Bootstrap();

    public Oauth2 getOauth2() {
        return oauth2;
    }

    public Jwt getJwt() {
        return jwt;
    }

    public Token getToken() {
        return token;
    }

    public Bootstrap getBootstrap() {
        return bootstrap;
    }

    public static class Oauth2 {
        private String issuer;
        private final PublicClient publicClient = new PublicClient();
        private final ServiceClient serviceClient = new ServiceClient();

        public String getIssuer() {
            return issuer;
        }

        public void setIssuer(String issuer) {
            this.issuer = issuer;
        }

        public PublicClient getPublicClient() {
            return publicClient;
        }

        public ServiceClient getServiceClient() {
            return serviceClient;
        }
    }

    public static class PublicClient {
        private String id;
        private List<String> redirectUris = new ArrayList<>();
        private List<String> scopes = new ArrayList<>();

        public String getId() {
            return id;
        }

        public void setId(String id) {
            this.id = id;
        }

        public List<String> getRedirectUris() {
            return redirectUris;
        }

        public void setRedirectUris(List<String> redirectUris) {
            this.redirectUris = redirectUris;
        }

        public List<String> getScopes() {
            return scopes;
        }

        public void setScopes(List<String> scopes) {
            this.scopes = scopes;
        }
    }

    public static class ServiceClient {
        private String id;
        private String secret;
        private List<String> scopes = new ArrayList<>();

        public String getId() {
            return id;
        }

        public void setId(String id) {
            this.id = id;
        }

        public String getSecret() {
            return secret;
        }

        public void setSecret(String secret) {
            this.secret = secret;
        }

        public List<String> getScopes() {
            return scopes;
        }

        public void setScopes(List<String> scopes) {
            this.scopes = scopes;
        }
    }

    public static class Jwt {
        private String audience;
        private List<String> resourceAudiences = new ArrayList<>();
        private String privateKey;
        private String publicKey;
        private String privateKeyLocation;
        private String publicKeyLocation;

        public String getAudience() {
            return audience;
        }

        public void setAudience(String audience) {
            this.audience = audience;
        }

        public List<String> getResourceAudiences() {
            return resourceAudiences;
        }

        public void setResourceAudiences(List<String> resourceAudiences) {
            this.resourceAudiences = resourceAudiences;
        }

        public String getPrivateKey() {
            return privateKey;
        }

        public void setPrivateKey(String privateKey) {
            this.privateKey = privateKey;
        }

        public String getPublicKey() {
            return publicKey;
        }

        public void setPublicKey(String publicKey) {
            this.publicKey = publicKey;
        }

        public String getPrivateKeyLocation() {
            return privateKeyLocation;
        }

        public void setPrivateKeyLocation(String privateKeyLocation) {
            this.privateKeyLocation = privateKeyLocation;
        }

        public String getPublicKeyLocation() {
            return publicKeyLocation;
        }

        public void setPublicKeyLocation(String publicKeyLocation) {
            this.publicKeyLocation = publicKeyLocation;
        }
    }

    public static class Token {
        private Duration accessTokenTimeToLive = Duration.ofMinutes(15);
        private Duration refreshTokenTimeToLive = Duration.ofHours(8);
        private Duration authorizationCodeTimeToLive = Duration.ofMinutes(2);

        public Duration getAccessTokenTimeToLive() {
            return accessTokenTimeToLive;
        }

        public void setAccessTokenTimeToLive(Duration accessTokenTimeToLive) {
            this.accessTokenTimeToLive = accessTokenTimeToLive;
        }

        public Duration getRefreshTokenTimeToLive() {
            return refreshTokenTimeToLive;
        }

        public void setRefreshTokenTimeToLive(Duration refreshTokenTimeToLive) {
            this.refreshTokenTimeToLive = refreshTokenTimeToLive;
        }

        public Duration getAuthorizationCodeTimeToLive() {
            return authorizationCodeTimeToLive;
        }

        public void setAuthorizationCodeTimeToLive(Duration authorizationCodeTimeToLive) {
            this.authorizationCodeTimeToLive = authorizationCodeTimeToLive;
        }
    }

    public static class Bootstrap {
        private String username;
        private String password;
        private String email;
        private String employeeUsername;
        private String employeePassword;
        private String employeeEmail;

        public String getUsername() {
            return username;
        }

        public void setUsername(String username) {
            this.username = username;
        }

        public String getPassword() {
            return password;
        }

        public void setPassword(String password) {
            this.password = password;
        }

        public String getEmail() {
            return email;
        }

        public void setEmail(String email) {
            this.email = email;
        }

        public String getEmployeeUsername() {
            return employeeUsername;
        }

        public void setEmployeeUsername(String employeeUsername) {
            this.employeeUsername = employeeUsername;
        }

        public String getEmployeePassword() {
            return employeePassword;
        }

        public void setEmployeePassword(String employeePassword) {
            this.employeePassword = employeePassword;
        }

        public String getEmployeeEmail() {
            return employeeEmail;
        }

        public void setEmployeeEmail(String employeeEmail) {
            this.employeeEmail = employeeEmail;
        }
    }
}
