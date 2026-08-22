package com.iotsecurity.auth.dto;

import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.NotBlank;

public class LoginRequest {

    @Schema(
            description = "Username used for authentication",
            example = "admin",
            requiredMode = Schema.RequiredMode.REQUIRED
    )
    @NotBlank(message = "Username is required")
    private String username;

    @Schema(
            description = "Password used for authentication",
            example = "Admin@123",
            requiredMode = Schema.RequiredMode.REQUIRED,
            format = "password"
    )
    @NotBlank(message = "Password is required")
    private String password;

    public LoginRequest() {
    }

    public String getUsername() {
        return username;
    }

    public String getPassword() {
        return password;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    public void setPassword(String password) {
        this.password = password;
    }
}