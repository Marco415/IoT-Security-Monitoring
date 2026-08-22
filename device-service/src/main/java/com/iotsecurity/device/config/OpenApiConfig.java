package com.iotsecurity.device.config;

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
    public OpenAPI deviceServiceOpenAPI() {
        return new OpenAPI()
                .info(new Info()
                        .title("IoT Security Monitoring - Device Service API")
                        .description(
                                "REST API for registering, retrieving, updating, " +
                                        "searching and deleting IoT devices in the IoT Security Monitoring System."
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