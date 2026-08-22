package com.iotsecurity.event.model;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.PrePersist;
import jakarta.persistence.Table;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;

import java.time.LocalDateTime;
import java.util.UUID;

@Entity
@Table(name = "security_events")
public class SecurityEvent {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "event_id", unique = true, nullable = false, length = 100)
    @NotBlank
    private String eventId;

    @Column(name = "device_id", nullable = false, length = 100)
    @NotBlank
    private String deviceId;

    @Enumerated(EnumType.STRING)
    @Column(name = "event_type", nullable = false, length = 50)
    @NotNull
    private EventType eventType;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false, length = 20)
    @NotNull
    private Severity severity;

    @Column(nullable = false, length = 1000)
    @NotBlank
    private String description;

    @Column(name = "source_ip", length = 100)
    private String sourceIp;

    @Column(nullable = false)
    private LocalDateTime timestamp;

    @Column(nullable = false, length = 30)
    @NotBlank
    private String status;

    public SecurityEvent() {
    }

    /**
     * Automatically generates values that are required when
     * a new security event is created.
     *
     * Status defaults to OPEN only when no status was supplied.
     * This means a supplied status such as RESOLVED or CLOSED
     * will NOT be overwritten.
     */
    @PrePersist
    public void generateEventId() {

        if (eventId == null || eventId.isBlank()) {
            eventId = "EVT-" + UUID.randomUUID();
        }

        if (timestamp == null) {
            timestamp = LocalDateTime.now();
        }

        if (status == null || status.isBlank()) {
            status = "OPEN";
        } else {
            status = status.trim().toUpperCase();
        }
    }

    public Long getId() {
        return id;
    }

    public String getEventId() {
        return eventId;
    }

    public void setEventId(String eventId) {
        this.eventId = eventId;
    }

    public String getDeviceId() {
        return deviceId;
    }

    public void setDeviceId(String deviceId) {
        this.deviceId = deviceId;
    }

    public EventType getEventType() {
        return eventType;
    }

    public void setEventType(EventType eventType) {
        this.eventType = eventType;
    }

    public Severity getSeverity() {
        return severity;
    }

    public void setSeverity(Severity severity) {
        this.severity = severity;
    }

    public String getDescription() {
        return description;
    }

    public void setDescription(String description) {
        this.description = description;
    }

    public String getSourceIp() {
        return sourceIp;
    }

    public void setSourceIp(String sourceIp) {
        this.sourceIp = sourceIp;
    }

    public LocalDateTime getTimestamp() {
        return timestamp;
    }

    public void setTimestamp(LocalDateTime timestamp) {
        this.timestamp = timestamp;
    }

    public String getStatus() {
        return status;
    }

    public void setStatus(String status) {

        if (status == null || status.isBlank()) {
            this.status = null;
            return;
        }

        this.status = status.trim().toUpperCase();
    }
}