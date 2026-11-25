package com.invex.test.authentication;

import com.invex.test.authentication.service.AccessControlCatalog;
import com.invex.test.authentication.service.UserAccountService;
import com.invex.test.authentication.domain.model.AuthenticationUser;
import com.invex.test.authentication.domain.model.Role;
import com.invex.test.authentication.repository.AuthenticationUserRepository;
import com.invex.test.authentication.security.AuthorizationCodes;
import com.jayway.jsonpath.JsonPath;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;

import java.net.URI;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.time.Duration;
import java.util.Base64;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
class AccountRulesTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private AccessControlCatalog catalog;

    @Autowired
    private UserAccountService userAccountService;

    private static final String PUBLIC_CLIENT = "employee-management-client";
    private static final String REDIRECT_URI = "http://localhost:8080/swagger-ui/oauth2-redirect.html";

    @Autowired
    private AuthenticationUserRepository userRepository;

    @Autowired
    private JwtDecoder jwtDecoder;

    @BeforeEach
    void setUpAccounts() {
        Role administrator = catalog.ensureRole(AuthorizationCodes.ADMINISTRATOR, "Administrator");
        Role employee = catalog.ensureRole(AuthorizationCodes.EMPLOYEE, "Employee");
        userAccountService.registerIfAbsent("admin", "admin", "admin@test.invex.local", true, Set.of(administrator));
        userAccountService.registerIfAbsent("employee", "employee", "employee@test.invex.local", true, Set.of(employee));
        userRepository.findByUsername("karla.chavez").ifPresent(userRepository::delete);
        userRepository.findByUsername("juan.perez").ifPresent(userRepository::delete);
    }

    @Test
    void disabledAccountCannotLogIn() throws Exception {
        userRepository.findByUsername("disabled.user").ifPresent(userRepository::delete);
        Role employee = catalog.ensureRole(AuthorizationCodes.EMPLOYEE, "Employee");
        userAccountService.registerIfAbsent(
                "disabled.user",
                "ChangeMe123!",
                "disabled.user@test.invex.local",
                false,
                Set.of(employee)
        );
        assertThat(userRepository.findByUsername("disabled.user").orElseThrow().isEnabled()).isFalse();

        String verifier = codeVerifier();
        MockHttpSession session = new MockHttpSession();
        MvcResult authorize = mockMvc.perform(authorizationRequest(session, codeChallenge(verifier)))
                .andExpect(status().isFound())
                .andReturn();
        session = currentSession(authorize, session);

        MvcResult login = mockMvc.perform(post("/login")
                        .session(session)
                        .with(csrf())
                        .param("username", "disabled.user")
                        .param("password", "ChangeMe123!"))
                .andExpect(status().isFound())
                .andReturn();

        assertThat(login.getResponse().getRedirectedUrl()).contains("error");
    }

    @Test
    void serviceClientReceivesAClientCredentialsToken() throws Exception {
        String credentials = Base64.getEncoder().encodeToString(
                "employee-service:test-service-secret".getBytes(StandardCharsets.UTF_8)
        );

        MvcResult tokenResponse = mockMvc.perform(post("/oauth2/token")
                        .header("Authorization", "Basic " + credentials)
                        .param("grant_type", "client_credentials")
                        .param("scope", "employees:read"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.access_token").isNotEmpty())
                .andExpect(jsonPath("$.token_type").value("Bearer"))
                .andReturn();
        String accessToken = JsonPath.read(tokenResponse.getResponse().getContentAsString(), "$.access_token");
        Jwt jwt = jwtDecoder.decode(accessToken);

        assertThat(jwt.getSubject()).isEqualTo("employee-service");
        assertThat(jwt.getAudience()).contains("authentication-service", "employee-service");
        assertThat(jwt.getClaimAsStringList("scope")).contains("employees:read");
        assertThat((Object) jwt.getClaim("roles")).isNull();

        mockMvc.perform(post("/api/v1/security/accounts")
                        .header("Authorization", "Bearer " + accessToken)
                        .contentType("application/json")
                        .content("""
                                {"username":"juan.perez","password":"ChangeMe123!","email":"juan.perez@test.invex.local","role":"EMPLOYEE"}
                                """))
                .andExpect(status().isForbidden());
    }

    @Test
    void adminOpensAnEmployeeAccount() throws Exception {
        String token = login("admin", "admin");

        mockMvc.perform(post("/api/v1/security/accounts")
                        .header("Authorization", "Bearer " + token)
                        .contentType("application/json")
                        .content("""
                                {"username":"karla.chavez","password":"ChangeMe123!","email":"karla.chavez@test.invex.local","role":"EMPLOYEE"}
                                """))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.username").value("karla.chavez"))
                .andExpect(jsonPath("$.email").value("karla.chavez@test.invex.local"))
                .andExpect(jsonPath("$.role").value("EMPLOYEE"))
                .andExpect(jsonPath("$.password").doesNotExist())
                .andExpect(jsonPath("$.passwordHash").doesNotExist());

        AuthenticationUser stored = userRepository.findByUsername("karla.chavez").orElseThrow();
        assertThat(stored.getPasswordHash()).startsWith("$2");
        assertThat(stored.getPasswordHash()).doesNotContain("ChangeMe123!");
    }

    @Test
    void rejectsARepeatedUsername() throws Exception {
        String token = login("admin", "admin");
        open(token, "karla.chavez", "karla.chavez@test.invex.local");

        mockMvc.perform(post("/api/v1/security/accounts")
                        .header("Authorization", "Bearer " + token)
                        .contentType("application/json")
                        .content("""
                                {"username":"karla.chavez","password":"ChangeMe123!","email":"juan.perez@test.invex.local","role":"EMPLOYEE"}
                                """))
                .andExpect(status().isConflict())
                .andExpect(jsonPath("$.message").value("Username is already registered"));
    }

    @Test
    void rejectsARepeatedEmail() throws Exception {
        String token = login("admin", "admin");
        open(token, "juan.perez", "juan.perez@test.invex.local");

        mockMvc.perform(post("/api/v1/security/accounts")
                        .header("Authorization", "Bearer " + token)
                        .contentType("application/json")
                        .content("""
                                {"username":"karla.chavez","password":"ChangeMe123!","email":"Juan.Perez@test.invex.local","role":"EMPLOYEE"}
                                """))
                .andExpect(status().isConflict())
                .andExpect(jsonPath("$.message").value("Email is already registered"));
    }

    @Test
    void refusesToOpenAnAdministratorAccount() throws Exception {
        String token = login("admin", "admin");

        mockMvc.perform(post("/api/v1/security/accounts")
                        .header("Authorization", "Bearer " + token)
                        .contentType("application/json")
                        .content("""
                                {"username":"karla.chavez","password":"ChangeMe123!","email":"karla.chavez@test.invex.local","role":"ADMIN"}
                                """))
                .andExpect(status().isForbidden());

        assertThat(userRepository.findByUsername("karla.chavez")).isEmpty();
    }

    @Test
    void onlyTheAdministratorCanOpenAnAccount() throws Exception {
        mockMvc.perform(post("/api/v1/security/accounts")
                        .contentType("application/json")
                        .content("""
                                {"username":"juan.perez","password":"ChangeMe123!","email":"juan.perez@test.invex.local","role":"EMPLOYEE"}
                                """))
                .andExpect(status().isUnauthorized());

        String employeeToken = login("employee", "employee");
        mockMvc.perform(post("/api/v1/security/accounts")
                        .header("Authorization", "Bearer " + employeeToken)
                        .contentType("application/json")
                        .content("""
                                {"username":"juan.perez","password":"ChangeMe123!","email":"juan.perez@test.invex.local","role":"EMPLOYEE"}
                                """))
                .andExpect(status().isForbidden());
        assertThat(userRepository.findByUsername("juan.perez")).isEmpty();
    }

    @Test
    void administratorDeletesAnAccount() throws Exception {
        String token = login("admin", "admin");
        open(token, "karla.chavez", "karla.chavez@test.invex.local");

        mockMvc.perform(delete("/api/v1/security/accounts/karla.chavez")
                        .header("Authorization", "Bearer " + token))
                .andExpect(status().isNoContent())
                .andExpect(content().string(""));

        assertThat(userRepository.findByUsername("karla.chavez")).isEmpty();
        assertThat(catalog.ensureRole(AuthorizationCodes.EMPLOYEE, "Employee").getCode())
                .isEqualTo(AuthorizationCodes.EMPLOYEE);
    }

    @Test
    void missingAccountReturnsNotFound() throws Exception {
        String token = login("admin", "admin");

        mockMvc.perform(delete("/api/v1/security/accounts/juan.perez")
                        .header("Authorization", "Bearer " + token))
                .andExpect(status().isNotFound())
                .andExpect(jsonPath("$.message").value("Account was not found"));
    }

    @Test
    void onlyTheAdministratorCanDeleteAnAccount() throws Exception {
        String adminToken = login("admin", "admin");
        open(adminToken, "karla.chavez", "karla.chavez@test.invex.local");

        mockMvc.perform(delete("/api/v1/security/accounts/karla.chavez"))
                .andExpect(status().isUnauthorized());

        String employeeToken = login("employee", "employee");
        mockMvc.perform(delete("/api/v1/security/accounts/karla.chavez")
                        .header("Authorization", "Bearer " + employeeToken))
                .andExpect(status().isForbidden());

        assertThat(userRepository.findByUsername("karla.chavez")).isPresent();
    }

    private String login(String username, String password) throws Exception {
        String verifier = codeVerifier();
        MockHttpSession session = new MockHttpSession();
        MvcResult authorize = mockMvc.perform(authorizationRequest(session, codeChallenge(verifier)))
                .andExpect(status().isFound())
                .andReturn();
        session = currentSession(authorize, session);
        assertThat(authorize.getResponse().getRedirectedUrl()).contains("/login");

        MvcResult login = mockMvc.perform(post("/login")
                        .session(session)
                        .with(csrf())
                        .param("username", username)
                        .param("password", password))
                .andExpect(status().isFound())
                .andReturn();
        session = currentSession(login, session);
        String location = login.getResponse().getRedirectedUrl();
        String code = null;
        for (int attempt = 0; attempt < 4 && code == null; attempt++) {
            if (location != null && location.contains("code=")) {
                code = queryParameter(location, "code");
                break;
            }
            MvcResult next = mockMvc.perform(follow(location).session(session).accept(MediaType.TEXT_HTML))
                    .andExpect(status().isFound())
                    .andReturn();
            session = currentSession(next, session);
            location = next.getResponse().getRedirectedUrl();
        }
        assertThat(code).isNotBlank();

        MvcResult tokenResponse = mockMvc.perform(post("/oauth2/token")
                        .param("grant_type", "authorization_code")
                        .param("code", code)
                        .param("redirect_uri", REDIRECT_URI)
                        .param("client_id", PUBLIC_CLIENT)
                        .param("code_verifier", verifier))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.token_type").value("Bearer"))
                .andReturn();
        return JsonPath.read(tokenResponse.getResponse().getContentAsString(), "$.access_token");
    }

    private static MockHttpServletRequestBuilder authorizationRequest(MockHttpSession session, String challenge) {
        return get("/oauth2/authorize")
                .session(session)
                .accept(MediaType.TEXT_HTML)
                .queryParam("response_type", "code")
                .queryParam("client_id", PUBLIC_CLIENT)
                .queryParam("redirect_uri", REDIRECT_URI)
                .queryParam("scope", "openid profile email")
                .queryParam("state", "login-state")
                .queryParam("code_challenge", challenge)
                .queryParam("code_challenge_method", "S256");
    }

    private static MockHttpServletRequestBuilder follow(String location) {
        URI uri = location.startsWith("http://") || location.startsWith("https://")
                ? URI.create(location)
                : URI.create("http://localhost" + (location.startsWith("/") ? location : "/" + location));
        MockHttpServletRequestBuilder request = get(uri.getRawPath());
        String query = uri.getRawQuery();
        if (query != null) {
            for (String pair : query.split("&")) {
                String[] parts = pair.split("=", 2);
                String name = URLDecoder.decode(parts[0], StandardCharsets.UTF_8);
                String value = parts.length == 2 ? URLDecoder.decode(parts[1], StandardCharsets.UTF_8) : "";
                request.queryParam(name, value);
            }
        }
        return request;
    }

    private static MockHttpSession currentSession(MvcResult result, MockHttpSession previous) {
        MockHttpSession current = (MockHttpSession) result.getRequest().getSession(false);
        return current == null ? previous : current;
    }

    private static String queryParameter(String location, String name) {
        URI uri = location.startsWith("http://") || location.startsWith("https://")
                ? URI.create(location)
                : URI.create("http://localhost" + location);
        for (String pair : uri.getRawQuery().split("&")) {
            String[] parts = pair.split("=", 2);
            if (name.equals(URLDecoder.decode(parts[0], StandardCharsets.UTF_8))) {
                return URLDecoder.decode(parts[1], StandardCharsets.UTF_8);
            }
        }
        return null;
    }

    private static String codeVerifier() {
        byte[] bytes = new byte[32];
        new SecureRandom().nextBytes(bytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }

    private static String codeChallenge(String verifier) throws Exception {
        byte[] digest = MessageDigest.getInstance("SHA-256").digest(verifier.getBytes(StandardCharsets.US_ASCII));
        return Base64.getUrlEncoder().withoutPadding().encodeToString(digest);
    }

    private void open(String token, String username, String email) throws Exception {
        mockMvc.perform(post("/api/v1/security/accounts")
                        .header("Authorization", "Bearer " + token)
                        .contentType("application/json")
                        .content("""
                                {"username":"%s","password":"ChangeMe123!","email":"%s","role":"EMPLOYEE"}
                                """.formatted(username, email)))
                .andExpect(status().isCreated());
    }
}
