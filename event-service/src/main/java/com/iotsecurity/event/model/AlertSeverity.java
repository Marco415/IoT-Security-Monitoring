package com.iotsecurity.event.model;

import io.swagger.v3.oas.annotations.media.Schema;

@Schema(
        description = "Alert severity type"
)

public enum AlertSeverity {
    LOW,
    MEDIUM,
    HIGH,
    CRITICAL
}