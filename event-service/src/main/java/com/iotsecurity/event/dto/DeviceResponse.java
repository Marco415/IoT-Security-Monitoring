package com.iotsecurity.event.dto;

public record DeviceResponse(

        Long id,
        String deviceId,
        String name,
        String deviceType,
        String status

) {
}