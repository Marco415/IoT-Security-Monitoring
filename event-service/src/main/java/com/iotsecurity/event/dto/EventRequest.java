package com.iotsecurity.event.dto;

import com.iotsecurity.event.model.EventType;
import com.iotsecurity.event.model.Severity;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Size;

public record EventRequest(

        @NotBlank(message = "deviceId is required")
        String deviceId,

        @NotNull(message = "eventType is required")
        EventType eventType,

        @NotNull(message = "severity is required")
        Severity severity,

        @NotBlank(message = "description is required")
        @Size(max = 1000, message = "description cannot exceed 1000 characters")
        String description,

        @Size(max = 100, message = "sourceIp cannot exceed 100 characters")
        String sourceIp
) {
}