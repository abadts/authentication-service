package com.invex.test.authentication.configuration;

import io.swagger.v3.oas.models.Components;
import io.swagger.v3.oas.models.OpenAPI;
import io.swagger.v3.oas.models.info.Info;
import io.swagger.v3.oas.models.security.OAuthFlow;
import io.swagger.v3.oas.models.security.OAuthFlows;
import io.swagger.v3.oas.models.security.Scopes;
import io.swagger.v3.oas.models.security.SecurityRequirement;
import io.swagger.v3.oas.models.security.SecurityScheme;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class OpenApiConfiguration {

    private static final String OAUTH2 = "oauth2";

    @Bean
    OpenAPI authenticationOpenApi(SecurityProperties properties) {
        String issuer = properties.getOauth2().getIssuer();
        return new OpenAPI()
                .info(new Info()
                        .title("Authentication Service")
                        .version("1.0.0")
                        .description("Authorize in Swagger with employee-management-client. Sign in as admin / admin."))
                .addSecurityItem(new SecurityRequirement().addList(OAUTH2))
                .components(new Components().addSecuritySchemes(OAUTH2, new SecurityScheme()
                        .type(SecurityScheme.Type.OAUTH2)
                        .flows(new OAuthFlows().authorizationCode(new OAuthFlow()
                                .authorizationUrl(issuer + "/oauth2/authorize")
                                .tokenUrl(issuer + "/oauth2/token")
                                .scopes(new Scopes()
                                        .addString("openid", "OpenID")
                                        .addString("profile", "Profile")
                                        .addString("email", "Email")
                                        .addString("employees:read", "Read employees")
                                        .addString("employees:write", "Write employees")
                                        .addString("employees:delete", "Delete employees"))))));
    }
}
