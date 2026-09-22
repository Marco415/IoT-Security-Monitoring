package com.iotsecurity.event.dto;

import com.iotsecurity.event.model.AlertSeverity;
import com.iotsecurity.event.model.AlertStatus;
import io.swagger.v3.oas.annotations.media.Schema;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;

import java.util.List;

@Schema(description = "Request used to create a SOC security alert")
public class AlertRequest {

    @NotBlank
    @Schema(example = "MULTIPLE_FAILED_LOGINS")
    private String ruleName;

    @NotNull
    @Schema(example = "HIGH")
    private AlertSeverity severity;

    @Schema(example = "OPEN")
    private AlertStatus status = AlertStatus.OPEN;

    @NotBlank
    @Schema(
            example = "Five failed login attempts detected from the same source IP within five minutes."
    )
    private String description;

    @Schema(example = "auth-service")
    private String affectedService;

    @Schema(example = "admin")
    private String affectedUser;

    @Schema(example = "login-endpoint")
    private String affectedEntity;

    @Schema(
            example = "Investigate the source IP, verify the account and consider temporary account or IP blocking."
    )
    private String recommendedAction;

    @Schema(
            description = "Event IDs associated with this alert"
    )
    private List<String> eventIds;

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

    public List<String> getEventIds() {
        return eventIds;
    }

    public void setEventIds(List<String> eventIds) {
        this.eventIds = eventIds;
    }
}