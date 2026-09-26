package com.iotsecurity.soc.model;

import jakarta.persistence.*;

import java.time.LocalDateTime;
import java.util.UUID;

@Entity
@Table(
        name = "soc_events",
        uniqueConstraints = {
                @UniqueConstraint(
                        name = "uk_soc_events_source_event",
                        columnNames = {
                                "source_system",
                                "source_event_id"
                        }
                )
        },
        indexes = {
                @Index(
                        name = "idx_soc_events_source_event",
                        columnList = "source_system, source_event_id"
                )
        }
)
public class SOCEvent {

    @Id
    @Column(name = "event_id", nullable = false, updatable = false)
    private UUID eventId;

    @Column(nullable = false)
    private LocalDateTime timestamp;

    @Column(nullable = false)
    private String serviceName;

    @Column(nullable = false)
    private String eventType;

    @Column(nullable = false)
    private String severity;

    private String userId;

    private String sourceIp;

    private String endpoint;

    private String httpMethod;

    private Integer statusCode;

    @Column(length = 2000)
    private String message;

    private String correlationId;

    private String affectedEntity;

    private Long sourceEventId;

    private String sourceSystem;

    public SOCEvent() {
    }

    public SOCEvent(
            UUID eventId,
            LocalDateTime timestamp,
            String serviceName,
            String eventType,
            String severity,
            String userId,
            String sourceIp,
            String endpoint,
            String httpMethod,
            Integer statusCode,
            String message,
            String correlationId,
            String affectedEntity
    ) {
        this.eventId = eventId;
        this.timestamp = timestamp;
        this.serviceName = serviceName;
        this.eventType = eventType;
        this.severity = severity;
        this.userId = userId;
        this.sourceIp = sourceIp;
        this.endpoint = endpoint;
        this.httpMethod = httpMethod;
        this.statusCode = statusCode;
        this.message = message;
        this.correlationId = correlationId;
        this.affectedEntity = affectedEntity;
    }

    public UUID getEventId() {
        return eventId;
    }

    public void setEventId(UUID eventId) {
        this.eventId = eventId;
    }

    public LocalDateTime getTimestamp() {
        return timestamp;
    }

    public void setTimestamp(LocalDateTime timestamp) {
        this.timestamp = timestamp;
    }

    public String getServiceName() {
        return serviceName;
    }

    public void setServiceName(String serviceName) {
        this.serviceName = serviceName;
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

    public String getUserId() {
        return userId;
    }

    public void setUserId(String userId) {
        this.userId = userId;
    }

    public String getSourceIp() {
        return sourceIp;
    }

    public void setSourceIp(String sourceIp) {
        this.sourceIp = sourceIp;
    }

    public String getEndpoint() {
        return endpoint;
    }

    public void setEndpoint(String endpoint) {
        this.endpoint = endpoint;
    }

    public String getHttpMethod() {
        return httpMethod;
    }

    public void setHttpMethod(String httpMethod) {
        this.httpMethod = httpMethod;
    }

    public Integer getStatusCode() {
        return statusCode;
    }

    public void setStatusCode(Integer statusCode) {
        this.statusCode = statusCode;
    }

    public String getMessage() {
        return message;
    }

    public void setMessage(String message) {
        this.message = message;
    }

    public String getCorrelationId() {
        return correlationId;
    }

    public void setCorrelationId(String correlationId) {
        this.correlationId = correlationId;
    }

    public String getAffectedEntity() {
        return affectedEntity;
    }

    public void setAffectedEntity(String affectedEntity) {
        this.affectedEntity = affectedEntity;
    }

    public Long getSourceEventId() {
        return sourceEventId;
    }

    public void setSourceEventId(Long sourceEventId) {
        this.sourceEventId = sourceEventId;
    }

    public String getSourceSystem() {
        return sourceSystem;
    }

    public void setSourceSystem(String sourceSystem) {
        this.sourceSystem = sourceSystem;
    }
}