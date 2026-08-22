package com.iotsecurity.gateway.security;

import java.util.List;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.reactive.CorsConfigurationSource;
import org.springframework.web.cors.reactive.UrlBasedCorsConfigurationSource;

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
                // CORS
                // =================================================

                .cors(
                        cors -> {
                        }
                )

                // =================================================
                // AUTHORIZATION
                // =================================================

                .authorizeExchange(exchange -> exchange

                        // =================================================
                        // CORS PREFLIGHT
                        // =================================================

                        .pathMatchers(
                                org.springframework.http.HttpMethod.OPTIONS,
                                "/**"
                        )
                        .permitAll()

                        // =================================================
                        // SWAGGER / OPENAPI
                        // =================================================

                        .pathMatchers(
                                "/swagger-ui.html",
                                "/swagger-ui/**",
                                "/v3/api-docs/**",

                                "/device-service/v3/api-docs",
                                "/event-service/v3/api-docs",
                                "/auth-service/v3/api-docs"
                        )
                        .permitAll()

                        // =================================================
                        // PUBLIC AUTHENTICATION ENDPOINTS
                        // =================================================

                        .pathMatchers(
                                "/api/auth/login",
                                "/api/auth/register"
                        )
                        .permitAll()

                        // =================================================
                        // PUBLIC HEALTH / INFO ENDPOINTS
                        // =================================================

                        .pathMatchers(
                                "/actuator/health",
                                "/actuator/info"
                        )
                        .permitAll()

                        // =================================================
                        // EVERYTHING ELSE REQUIRES JWT
                        // =================================================

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


    // =============================================================
    // CORS CONFIGURATION
    // =============================================================

    @Bean
    public CorsConfigurationSource corsConfigurationSource() {

        CorsConfiguration configuration =
                new CorsConfiguration();


        // ---------------------------------------------------------
        // ALLOWED CLIENT ORIGINS
        // ---------------------------------------------------------

        configuration.setAllowedOrigins(
                List.of(
                        "http://localhost:5500",
                        "http://127.0.0.1:5500"
                )
        );


        // ---------------------------------------------------------
        // ALLOWED HTTP METHODS
        // ---------------------------------------------------------

        configuration.setAllowedMethods(
                List.of(
                        "GET",
                        "POST",
                        "PUT",
                        "PATCH",
                        "DELETE",
                        "OPTIONS"
                )
        );


        // ---------------------------------------------------------
        // ALLOWED HEADERS
        // ---------------------------------------------------------

        configuration.setAllowedHeaders(
                List.of("*")
        );


        // ---------------------------------------------------------
        // EXPOSED HEADERS
        // ---------------------------------------------------------

        configuration.setExposedHeaders(
                List.of(
                        "Authorization"
                )
        );


        // ---------------------------------------------------------
        // CREDENTIALS
        // ---------------------------------------------------------

        configuration.setAllowCredentials(true);


        // ---------------------------------------------------------
        // REGISTER CORS CONFIGURATION
        // ---------------------------------------------------------

        UrlBasedCorsConfigurationSource source =
                new UrlBasedCorsConfigurationSource();


        source.registerCorsConfiguration(
                "/**",
                configuration
        );


        return source;
    }
}