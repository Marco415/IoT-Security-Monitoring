package com.iotsecurity.soc.dto.dashboard;

import io.swagger.v3.oas.annotations.media.Schema;

import java.time.LocalDateTime;
import java.util.UUID;

@Schema(description = "Alert displayed by the SOC dashboard.")
public record DashboardAlertResponse(

        UUID alertId,

        String rule,

        String severity,

        String serviceName,

        String userId,

        String status,

        LocalDateTime timestamp
) {
}