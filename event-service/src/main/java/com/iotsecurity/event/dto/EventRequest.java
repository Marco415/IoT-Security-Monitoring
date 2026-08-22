package com.iotsecurity.event.dto;

import com.iotsecurity.event.model.EventType;
import com.iotsecurity.event.model.Severity;
import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Size;

public record EventRequest(

        @Schema(
                description = "Unique identifier of the IoT device that generated the event",
                example = "DEV-001",
                requiredMode = Schema.RequiredMode.REQUIRED
        )
        @NotBlank(message = "deviceId is required")
        String deviceId,

        @Schema(
                description = "Type of security event detected",
                example = "FAILED_LOGIN",
                requiredMode = Schema.RequiredMode.REQUIRED
        )
        @NotNull(message = "eventType is required")
        EventType eventType,

        @Schema(
                description = "Severity level of the security event",
                example = "HIGH",
                requiredMode = Schema.RequiredMode.REQUIRED
        )
        @NotNull(message = "severity is required")
        Severity severity,

        @Schema(
                description = "Detailed description of the security event",
                example = "Multiple failed login attempts detected from the device",
                maxLength = 1000,
                requiredMode = Schema.RequiredMode.REQUIRED
        )
        @NotBlank(message = "description is required")
        @Size(
                max = 1000,
                message = "description cannot exceed 1000 characters"
        )
        String description,

        @Schema(
                description = "Source IP address associated with the security event",
                example = "192.168.1.100",
                maxLength = 100
        )
        @Size(
                max = 100,
                message = "sourceIp cannot exceed 100 characters"
        )
        String sourceIp,

        @Schema(
                description = "Current status of the security event. If omitted when creating an event, the status defaults to OPEN.",
                example = "RESOLVED",
                allowableValues = {
                        "OPEN",
                        "ACKNOWLEDGED",
                        "IN_PROGRESS",
                        "RESOLVED",
                        "CLOSED"
                }
        )
        @Size(
                max = 30,
                message = "status cannot exceed 30 characters"
        )
        String status

) {
}