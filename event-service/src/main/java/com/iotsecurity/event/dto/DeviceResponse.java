package com.iotsecurity.event.dto;

import io.swagger.v3.oas.annotations.media.Schema;

public record DeviceResponse(

        @Schema(
                description = "Database ID of the device",
                example = "1"
        )
        Long id,

        @Schema(
                description = "Unique IoT device identifier",
                example = "DEV-001"
        )
        String deviceId,

        @Schema(
                description = "Human-readable device name",
                example = "Airport Camera 01"
        )
        String name,

        @Schema(
                description = "Type of IoT device",
                example = "CAMERA"
        )
        String deviceType,

        @Schema(
                description = "Current status of the device",
                example = "ONLINE"
        )
        String status

) {
}