package com.iotsecurity.event.model;

import io.swagger.v3.oas.annotations.media.Schema;

@Schema(
        description = "Severity level assigned to a security event"
)
public enum Severity {

    @Schema(description = "Low severity security event")
    LOW,

    @Schema(description = "Medium severity security event")
    MEDIUM,

    @Schema(description = "High severity security event")
    HIGH,

    @Schema(description = "Critical security event requiring immediate attention")
    CRITICAL
}