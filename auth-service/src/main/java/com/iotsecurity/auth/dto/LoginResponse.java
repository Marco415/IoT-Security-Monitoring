package com.iotsecurity.auth.dto;

import io.swagger.v3.oas.annotations.media.Schema;

public class LoginResponse {

    @Schema(
            description = "JWT access token used to authenticate subsequent API requests",
            example = "eyJhbGciOiJIUzI1NiJ9..."
    )
    private final String token;

    @Schema(
            description = "Username of the authenticated user",
            example = "admin"
    )
    private final String username;

    @Schema(
            description = "Role assigned to the authenticated user",
            example = "ADMIN"
    )
    private final String role;

    public LoginResponse(
            String token,
            String username,
            String role
    ) {
        this.token = token;
        this.username = username;
        this.role = role;
    }

    public String getToken() {
        return token;
    }

    public String getUsername() {
        return username;
    }

    public String getRole() {
        return role;
    }
}