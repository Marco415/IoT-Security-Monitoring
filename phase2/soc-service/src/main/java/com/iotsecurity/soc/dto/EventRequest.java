package com.iotsecurity.soc.dto;

import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.NotBlank;

import java.time.LocalDateTime;

@Schema(
        description = "Request used to submit a security event to the SOC service."
)
public record EventRequest(

        @Schema(
                description = "Timestamp when the security event occurred. " +
                        "If omitted, the SOC service uses the current timestamp.",
                example = "2026-09-21T16:20:00"
        )
        LocalDateTime timestamp,

        @Schema(
                description = "Name of the service that generated the event.",
                example = "auth-service",
                requiredMode = Schema.RequiredMode.REQUIRED
        )
        @NotBlank
        String serviceName,

        @Schema(
                description = "Type of security event.",
                example = "FAILED_LOGIN",
                allowableValues = {
                        "FAILED_LOGIN",
                        "UNAUTHORIZED_ACCESS",
                        "BRUTE_FORCE",
                        "PORT_SCAN",
                        "DEVICE_TAMPERING",
                        "MALWARE_DETECTED",
                        "SUSPICIOUS_NETWORK_ACTIVITY",
                        "DATA_EXFILTRATION",
                        "POLICY_VIOLATION",
                        "ANOMALOUS_BEHAVIOR",
                        "DEVICE_OFFLINE",
                        "OTHER"
                },
                requiredMode = Schema.RequiredMode.REQUIRED
        )
        @NotBlank
        String eventType,

        @Schema(
                description = "Severity assigned to the security event.",
                example = "HIGH",
                allowableValues = {
                        "LOW",
                        "MEDIUM",
                        "HIGH",
                        "CRITICAL"
                },
                requiredMode = Schema.RequiredMode.REQUIRED
        )
        @NotBlank
        String severity,

        @Schema(
                description = "User associated with the security event.",
                example = "admin"
        )
        String userId,

        @Schema(
                description = "Source IP address associated with the event.",
                example = "192.168.1.100"
        )
        String sourceIp,

        @Schema(
                description = "API endpoint involved in the event.",
                example = "/api/devices"
        )
        String endpoint,

        @Schema(
                description = "HTTP method associated with the event.",
                example = "POST"
        )
        String httpMethod,

        @Schema(
                description = "HTTP response status code associated with the event.",
                example = "401"
        )
        Integer statusCode,

        @Schema(
                description = "Human-readable description of the security event.",
                example = "Failed login attempt for user admin."
        )
        String message,

        @Schema(
                description = "Identifier used to correlate related events across services.",
                example = "7b3d9a4e-7f41-4b9a-9d7e-123456789abc"
        )
        String correlationId,

        @Schema(
                description = "Entity affected by the security event.",
                example = "user:admin"
        )
        String affectedEntity
) {
}