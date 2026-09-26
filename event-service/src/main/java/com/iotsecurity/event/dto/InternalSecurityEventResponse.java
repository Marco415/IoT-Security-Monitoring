package com.iotsecurity.event.dto;

import java.time.LocalDateTime;

/**
 * DTO exposed by event-service to trusted internal consumers such as
 * the SOC service.
 *
 * IMPORTANT:
 * This DTO is deliberately separate from the JPA SecurityEvent entity.
 * The event-service remains the owner of its database model.
 */
public class InternalSecurityEventResponse {

    private Long id;

    private String eventId;

    private String description;

    private String deviceId;

    private String eventType;

    private String severity;

    private String sourceIp;

    private String status;

    private LocalDateTime timestamp;


    public InternalSecurityEventResponse() {
    }


    public Long getId() {
        return id;
    }

    public void setId(Long id) {
        this.id = id;
    }


    public String getEventId() {
        return eventId;
    }

    public void setEventId(String eventId) {
        this.eventId = eventId;
    }


    public String getDescription() {
        return description;
    }

    public void setDescription(String description) {
        this.description = description;
    }


    public String getDeviceId() {
        return deviceId;
    }

    public void setDeviceId(String deviceId) {
        this.deviceId = deviceId;
    }


    public String getEventType() {
        return eventType;
    }

    public void setEventType(String eventType) {
        this.eventType = eventType;
    }


    public String getSeverity() {
        return severity;
    }

    public void setSeverity(String severity) {
        this.severity = severity;
    }


    public String getSourceIp() {
        return sourceIp;
    }

    public void setSourceIp(String sourceIp) {
        this.sourceIp = sourceIp;
    }


    public String getStatus() {
        return status;
    }

    public void setStatus(String status) {
        this.status = status;
    }


    public LocalDateTime getTimestamp() {
        return timestamp;
    }

    public void setTimestamp(LocalDateTime timestamp) {
        this.timestamp = timestamp;
    }
}