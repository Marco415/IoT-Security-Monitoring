package com.iotsecurity.auth.entity;

import jakarta.persistence.*;

import java.time.LocalDateTime;

@Entity
@Table(name = "auth_events")
public class AuthEvent {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false)
    private String eventType;

    @Column(nullable = false)
    private String username;

    @Column(nullable = false)
    private String sourceIp;

    @Column(nullable = false)
    private LocalDateTime timestamp;

    @Column(nullable = false)
    private String result;

    @Column(nullable = false)
    private String service;

    public AuthEvent() {
    }

    public AuthEvent(
            String eventType,
            String username,
            String sourceIp,
            LocalDateTime timestamp,
            String result,
            String service
    ) {
        this.eventType = eventType;
        this.username = username;
        this.sourceIp = sourceIp;
        this.timestamp = timestamp;
        this.result = result;
        this.service = service;
    }

    public Long getId() {
        return id;
    }

    public String getEventType() {
        return eventType;
    }

    public String getUsername() {
        return username;
    }

    public String getSourceIp() {
        return sourceIp;
    }

    public LocalDateTime getTimestamp() {
        return timestamp;
    }

    public String getResult() {
        return result;
    }

    public String getService() {
        return service;
    }
}