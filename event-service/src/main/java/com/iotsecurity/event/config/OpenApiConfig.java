package com.iotsecurity.event.config;

import io.swagger.v3.oas.models.Components;
import io.swagger.v3.oas.models.OpenAPI;
import io.swagger.v3.oas.models.info.Contact;
import io.swagger.v3.oas.models.info.Info;
import io.swagger.v3.oas.models.info.License;
import io.swagger.v3.oas.models.security.SecurityScheme;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class OpenApiConfig {

    @Bean
    public OpenAPI eventServiceOpenAPI() {
        return new OpenAPI()
                .info(new Info()
                        .title("IoT Security Monitoring - Event Service API")
                        .description(
                                "REST API for creating, retrieving, searching, " +
                                        "updating and deleting IoT security events."
                        )
                        .version("1.0.0")
                        .contact(new Contact()
                                .name("IoT Security Monitoring Team"))
                        .license(new License()
                                .name("Project License")))
                .components(new Components()
                        .addSecuritySchemes(
                                "bearerAuth",
                                new SecurityScheme()
                                        .type(SecurityScheme.Type.HTTP)
                                        .scheme("bearer")
                                        .bearerFormat("JWT")
                        )
                );
    }
}