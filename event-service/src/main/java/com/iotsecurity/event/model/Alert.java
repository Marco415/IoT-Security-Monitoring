package com.iotsecurity.event.model;

import jakarta.persistence.*;

import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;

@Entity
@Table(
        name = "alerts",
        uniqueConstraints = {
                @UniqueConstraint(
                        name = "uk_alerts_alert_id",
                        columnNames = "alert_id"
                )
        },
        indexes = {
        @Index(name = "idx_alerts_timestamp", columnList = "timestamp"),
        @Index(name = "idx_alerts_rule_name", columnList = "rule_name"),
        @Index(name = "idx_alerts_severity", columnList = "severity"),
        @Index(name = "idx_alerts_status", columnList = "status")
    }
)
public class Alert {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "alert_id", nullable = false, unique = true, length = 100)
    private String alertId;

    @Column(nullable = false)
    private LocalDateTime timestamp;

    @Column(name = "rule_name", nullable = false, length = 100)
    private String ruleName;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false, length = 20)
    private AlertSeverity severity;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false, length = 30)
    private AlertStatus status = AlertStatus.OPEN;

    @Column(nullable = false, columnDefinition = "TEXT")
    private String description;

    @Column(name = "affected_service", length = 100)
    private String affectedService;

    @Column(name = "affected_user", length = 100)
    private String affectedUser;

    @Column(name = "affected_entity", length = 255)
    private String affectedEntity;

    @Column(name = "recommended_action", columnDefinition = "TEXT")
    private String recommendedAction;

    public Alert() {
    }

    public Long getId() {
        return id;
    }

    public String getAlertId() {
        return alertId;
    }

    public void setAlertId(String alertId) {
        this.alertId = alertId;
    }

    public LocalDateTime getTimestamp() {
        return timestamp;
    }

    public void setTimestamp(LocalDateTime timestamp) {
        this.timestamp = timestamp;
    }

    public String getRuleName() {
        return ruleName;
    }

    public void setRuleName(String ruleName) {
        this.ruleName = ruleName;
    }

    public AlertSeverity getSeverity() {
        return severity;
    }

    public void setSeverity(AlertSeverity severity) {
        this.severity = severity;
    }

    public AlertStatus getStatus() {
        return status;
    }

    public void setStatus(AlertStatus status) {
        this.status = status;
    }

    public String getDescription() {
        return description;
    }

    public void setDescription(String description) {
        this.description = description;
    }

    public String getAffectedService() {
        return affectedService;
    }

    public void setAffectedService(String affectedService) {
        this.affectedService = affectedService;
    }

    public String getAffectedUser() {
        return affectedUser;
    }

    public void setAffectedUser(String affectedUser) {
        this.affectedUser = affectedUser;
    }

    public String getAffectedEntity() {
        return affectedEntity;
    }

    public void setAffectedEntity(String affectedEntity) {
        this.affectedEntity = affectedEntity;
    }

    public String getRecommendedAction() {
        return recommendedAction;
    }

    public void setRecommendedAction(String recommendedAction) {
        this.recommendedAction = recommendedAction;
    }
}