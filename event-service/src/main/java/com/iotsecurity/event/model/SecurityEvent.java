package com.iotsecurity.event.model;

import jakarta.persistence.*;
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

    @Column(unique = true, nullable = false)
    @NotBlank
    private String eventId;

    @Column(nullable = false)
    @NotBlank
    private String deviceId;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false)
    @NotNull
    private EventType eventType;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false)
    @NotNull
    private Severity severity;

    @Column(nullable = false, length = 1000)
    @NotBlank
    private String description;

    private String sourceIp;

    @Column(nullable = false)
    private LocalDateTime timestamp;

    @Column(nullable = false)
    @NotBlank
    private String status;

    public SecurityEvent() {
    }

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
        this.status = status;
    }
}