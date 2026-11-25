package com.invex.test.authentication;

import com.invex.test.authentication.configuration.EnvironmentFileLoader;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

import java.nio.file.Path;

@SpringBootApplication
public class AuthenticationServiceApplication {

    public static void main(String[] applicationArguments) {
        new EnvironmentFileLoader().load(Path.of(".env"));
        SpringApplication.run(AuthenticationServiceApplication.class, applicationArguments);
    }
}
