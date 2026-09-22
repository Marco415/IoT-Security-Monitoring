package com.iotsecurity.event.model;

import jakarta.persistence.*;

@Entity
@Table(
        name = "alert_events",
        uniqueConstraints = {
                @UniqueConstraint(
                        name = "uk_alert_event",
                        columnNames = {"alert_id", "event_id"}
                )
        },
        indexes = {
                @Index(name = "idx_alert_events_event_id", columnList = "event_id")
        }
)
public class AlertEvent {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "alert_id", nullable = false, length = 100)
    private String alertId;

    @Column(name = "event_id", nullable = false, length = 100)
    private String eventId;

    public AlertEvent() {
    }

    public AlertEvent(String alertId, String eventId) {
        this.alertId = alertId;
        this.eventId = eventId;
    }

    public Long getId() {
        return id;
    }

    public String getAlertId() {
        return alertId;
    }

    public String getEventId() {
        return eventId;
    }

    public void setAlertId(String alertId) {
        this.alertId = alertId;
    }

    public void setEventId(String eventId) {
        this.eventId = eventId;
    }
}