package com.iotsecurity.soc.dto.dashboard;

import io.swagger.v3.oas.annotations.media.Schema;

@Schema(description = "Service health displayed by the SOC dashboard.")
public record DashboardServiceResponse(

        String name,

        String status
) {
}