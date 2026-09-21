package com.iotsecurity.soc.model;

import io.swagger.v3.oas.annotations.media.Schema;

@Schema(
        description = "Severity level assigned to a security event or SOC alert."
)
public enum Severity {

    @Schema(description = "Low severity security event.")
    LOW,

    @Schema(description = "Medium severity security event.")
    MEDIUM,

    @Schema(description = "High severity security event.")
    HIGH,

    @Schema(description = "Critical severity security event.")
    CRITICAL
}