package com.iotsecurity.auth.dto;

import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;

@Schema(
        name = "RegisterRequest",
        description = "Request payload used to register a new user"
)
public record RegisterRequest(

        @Schema(
                description = "Unique username for the new user",
                example = "admin",
                requiredMode = Schema.RequiredMode.REQUIRED,
                minLength = 3,
                maxLength = 50
        )
        @NotBlank(message = "username is required")
        @Size(min = 3, max = 50, message = "username must be between 3 and 50 characters")
        String username,

        @Schema(
                description = "Password for the new user account",
                example = "Admin123!",
                requiredMode = Schema.RequiredMode.REQUIRED,
                minLength = 6,
                maxLength = 100,
                format = "password"
        )
        @NotBlank(message = "password is required")
        @Size(min = 6, max = 100, message = "password must be between 6 and 100 characters")
        String password,

        @Schema(
                description = "Role assigned to the new user",
                example = "USER",
                allowableValues = {"USER", "ADMIN"},
                requiredMode = Schema.RequiredMode.REQUIRED
        )
        @NotBlank(message = "role is required")
        @Pattern(
                regexp = "USER|ADMIN",
                message = "role must be USER or ADMIN"
        )
        String role
) {
}