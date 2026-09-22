package com.iotsecurity.event.model;

import io.swagger.v3.oas.annotations.media.Schema;

@Schema(
        description = "Alert status type"
)

public enum AlertStatus {
    OPEN,
    INVESTIGATING,
    RESOLVED,
    CLOSED
}