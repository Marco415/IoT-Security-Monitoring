package com.iotsecurity.gateway.security;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.ServerHttpSecurity;

import org.springframework.security.web.server.SecurityWebFilterChain;

@Configuration
@EnableWebFluxSecurity
public class SecurityConfig {

    @Bean
    public SecurityWebFilterChain securityWebFilterChain(
            ServerHttpSecurity http
    ) {

        return http

                // =================================================
                // CSRF
                // =================================================

                .csrf(
                        ServerHttpSecurity.CsrfSpec::disable
                )

                // =================================================
                // AUTHORIZATION
                // =================================================

                .authorizeExchange(exchange -> exchange

                        // Public authentication endpoints
                        .pathMatchers(
                                "/api/auth/login",
                                "/api/auth/register"
                        )
                        .permitAll()

                        // Public health/info endpoints
                        .pathMatchers(
                                "/actuator/health",
                                "/actuator/info"
                        )
                        .permitAll()

                        // Everything else requires JWT
                        .anyExchange()
                        .authenticated()
                )

                // =================================================
                // JWT RESOURCE SERVER
                // =================================================

                .oauth2ResourceServer(
                        oauth2 -> oauth2.jwt(
                                jwt -> {
                                }
                        )
                )

                // =================================================
                // BUILD
                // =================================================

                .build();
    }
}