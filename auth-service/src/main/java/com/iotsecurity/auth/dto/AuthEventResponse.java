package com.iotsecurity.auth.dto;

import com.iotsecurity.auth.entity.AuthEvent;

import java.time.LocalDateTime;

public record AuthEventResponse(
        Long id,
        String eventType,
        String username,
        String sourceIp,
        LocalDateTime timestamp,
        String result,
        String service
) {

    public static AuthEventResponse fromEntity(AuthEvent event) {
        return new AuthEventResponse(
                event.getId(),
                event.getEventType(),
                event.getUsername(),
                event.getSourceIp(),
                event.getTimestamp(),
                event.getResult(),
                event.getService()
        );
    }
}