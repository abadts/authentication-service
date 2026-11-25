package com.invex.test.authentication.configuration;

import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.core.annotation.Order;
import org.springframework.core.io.ClassPathResource;
import org.springframework.jdbc.datasource.init.ResourceDatabasePopulator;
import org.springframework.stereotype.Component;

import javax.sql.DataSource;
import java.sql.Connection;
import java.sql.DatabaseMetaData;
import java.sql.ResultSet;
import java.sql.SQLException;

@Component
@Order(0)
public class AuthorizationSchemaInitializer implements ApplicationRunner {

    static final String REGISTERED_CLIENT_TABLE = "oauth2_registered_client";
    private static final String REGISTERED_CLIENT_SCHEMA =
            "org/springframework/security/oauth2/server/authorization/client/oauth2-registered-client-schema.sql";
    private static final String AUTHORIZATION_SCHEMA =
            "org/springframework/security/oauth2/server/authorization/oauth2-authorization-schema.sql";
    private static final String CONSENT_SCHEMA =
            "org/springframework/security/oauth2/server/authorization/oauth2-authorization-consent-schema.sql";

    private final DataSource dataSource;

    public AuthorizationSchemaInitializer(DataSource dataSource) {
        this.dataSource = dataSource;
    }

    @Override
    public void run(ApplicationArguments arguments) {
        initialize();
    }

    public void initialize() {
        if (tableExists()) {
            return;
        }
        ResourceDatabasePopulator populator = new ResourceDatabasePopulator();
        populator.addScript(new ClassPathResource(REGISTERED_CLIENT_SCHEMA));
        populator.addScript(new ClassPathResource(AUTHORIZATION_SCHEMA));
        populator.addScript(new ClassPathResource(CONSENT_SCHEMA));
        populator.setContinueOnError(false);
        populator.execute(dataSource);
    }

    private boolean tableExists() {
        try (Connection connection = dataSource.getConnection()) {
            DatabaseMetaData metadata = connection.getMetaData();
            return hasTable(metadata, REGISTERED_CLIENT_TABLE)
                    || hasTable(metadata, REGISTERED_CLIENT_TABLE.toUpperCase());
        } catch (SQLException exception) {
            throw new IllegalStateException("Unable to inspect authorization tables", exception);
        }
    }

    private static boolean hasTable(DatabaseMetaData metadata, String tableName) throws SQLException {
        try (ResultSet tables = metadata.getTables(null, null, tableName, new String[]{"TABLE"})) {
            return tables.next();
        }
    }
}
