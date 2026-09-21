package com.iotsecurity.soc.config;

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
    public OpenAPI socOpenAPI() {

        return new OpenAPI()
                .info(new Info()
                        .title("IoT Security Monitoring - SOC API")
                        .description(
                                "Security Operations Centre API for " +
                                        "event normalization, detection and alerting."
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