package com.invex.test.authentication.configuration;

import com.invex.test.authentication.service.AccessControlCatalog;
import com.invex.test.authentication.service.UserAccountService;
import com.invex.test.authentication.domain.model.Role;
import com.invex.test.authentication.security.AuthorizationCodes;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.context.annotation.Profile;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;

import java.util.Set;

@Component
@Profile("local")
@Order(2)
public class IdentityBootstrap implements ApplicationRunner {

    private final AccessControlCatalog catalog;
    private final UserAccountService userAccountService;
    private final SecurityProperties properties;

    public IdentityBootstrap(AccessControlCatalog catalog,
                             UserAccountService userAccountService,
                             SecurityProperties properties) {
        this.catalog = catalog;
        this.userAccountService = userAccountService;
        this.properties = properties;
    }

    @Override
    public void run(ApplicationArguments arguments) {
        Role employee = catalog.ensureRole(AuthorizationCodes.EMPLOYEE, "Employee");
        Role administrator = catalog.ensureRole(AuthorizationCodes.ADMINISTRATOR, "Administrator");
        SecurityProperties.Bootstrap bootstrap = properties.getBootstrap();
        userAccountService.registerIfAbsent(
                bootstrap.getUsername(),
                bootstrap.getPassword(),
                bootstrap.getEmail(),
                true,
                Set.of(administrator)
        );
        userAccountService.registerIfAbsent(
                bootstrap.getEmployeeUsername(),
                bootstrap.getEmployeePassword(),
                bootstrap.getEmployeeEmail(),
                true,
                Set.of(employee)
        );
    }
}
