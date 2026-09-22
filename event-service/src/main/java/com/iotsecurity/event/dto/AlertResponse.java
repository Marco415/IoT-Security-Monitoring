package com.iotsecurity.event.dto;

import com.iotsecurity.event.model.AlertSeverity;
import com.iotsecurity.event.model.AlertStatus;
import io.swagger.v3.oas.annotations.media.Schema;

import java.time.LocalDateTime;
import java.util.List;

@Schema(description = "Security alert returned by the event service")
public record AlertResponse(

        String alertId,

        LocalDateTime timestamp,

        String ruleName,

        AlertSeverity severity,

        AlertStatus status,

        String description,

        String affectedService,

        String affectedUser,

        String affectedEntity,

        String recommendedAction,

        List<String> eventIds
) {
}