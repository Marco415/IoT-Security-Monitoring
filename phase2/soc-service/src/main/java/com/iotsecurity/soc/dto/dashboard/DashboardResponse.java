package com.iotsecurity.soc.dto.dashboard;

import io.swagger.v3.oas.annotations.media.Schema;

import java.time.LocalDateTime;
import java.util.List;

@Schema(description = "SOC dashboard summary.")
public record DashboardResponse(

        @Schema(
                description = "Total number of normalized SOC events."
        )
        long totalEvents,

        @Schema(
                description = "Number of currently open alerts."
        )
        long openAlerts,

        @Schema(
                description = "Number of high-severity alerts."
        )
        long highAlerts,

        @Schema(
                description = "Number of medium-severity alerts."
        )
        long mediumAlerts,

        @Schema(
                description = "Current service health information."
        )
        List<DashboardServiceResponse> services,

        @Schema(
                description = "Most recent SOC alerts."
        )
        List<DashboardAlertResponse> recentAlerts,

        @Schema(
                description = "Time at which this dashboard response was generated."
        )
        LocalDateTime generatedAt
) {
}