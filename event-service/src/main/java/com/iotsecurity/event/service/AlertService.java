package com.iotsecurity.event.service;

import com.iotsecurity.event.dto.AlertResponse;
import com.iotsecurity.event.dto.AlertRequest;
import com.iotsecurity.event.model.Alert;
import com.iotsecurity.event.model.AlertEvent;
import com.iotsecurity.event.model.AlertStatus;
import com.iotsecurity.event.repository.AlertEventRepository;
import com.iotsecurity.event.repository.AlertRepository;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.List;
import java.util.UUID;

@Service
public class AlertService {

    private static final Logger log =
            LoggerFactory.getLogger(AlertService.class);

    private final AlertRepository alertRepository;
    private final AlertEventRepository alertEventRepository;

    public AlertService(
            AlertRepository alertRepository,
            AlertEventRepository alertEventRepository
    ) {
        this.alertRepository = alertRepository;
        this.alertEventRepository = alertEventRepository;
    }

    @Transactional
    public AlertResponse createAlert(AlertRequest request) {

        String alertId =
                "alert-" + UUID.randomUUID();

        Alert alert = new Alert();

        alert.setAlertId(alertId);
        alert.setTimestamp(LocalDateTime.now());
        alert.setRuleName(request.getRuleName());
        alert.setSeverity(request.getSeverity());
        alert.setStatus(
                request.getStatus() != null
                        ? request.getStatus()
                        : AlertStatus.OPEN
        );
        alert.setDescription(request.getDescription());
        alert.setAffectedService(request.getAffectedService());
        alert.setAffectedUser(request.getAffectedUser());
        alert.setAffectedEntity(request.getAffectedEntity());
        alert.setRecommendedAction(request.getRecommendedAction());

        Alert savedAlert = alertRepository.save(alert);

        log.info(
                "SOC_ALERT_CREATED alertId={} ruleName={} severity={} status={} affectedService={} affectedUser={} affectedEntity={}",
                savedAlert.getAlertId(),
                savedAlert.getRuleName(),
                savedAlert.getSeverity(),
                savedAlert.getStatus(),
                savedAlert.getAffectedService(),
                savedAlert.getAffectedUser(),
                savedAlert.getAffectedEntity()
        );

        if (request.getEventIds() != null) {

            for (String eventId : request.getEventIds()) {

                if (!alertEventRepository
                        .existsByAlertIdAndEventId(
                                alertId,
                                eventId
                        )) {

                    alertEventRepository.save(
                            new AlertEvent(
                                    alertId,
                                    eventId
                            )
                    );

                    log.info(
                            "SOC_ALERT_EVENT_LINKED alertId={} eventId={}",
                            alertId,
                            eventId
                    );
                }
            }
        }

        return getAlert(alertId);
    }

    @Transactional(readOnly = true)
    public List<AlertResponse> getAllAlerts() {

        return alertRepository.findAll()
                .stream()
                .map(this::toResponse)
                .toList();
    }

    @Transactional(readOnly = true)
    public AlertResponse getAlert(String alertId) {

        Alert alert = alertRepository
                .findByAlertId(alertId)
                .orElseThrow(
                        () -> new IllegalArgumentException(
                                "Alert not found: " + alertId
                        )
                );

        return toResponse(alert);
    }

    @Transactional
    public AlertResponse updateStatus(
            String alertId,
            AlertStatus status
    ) {

        Alert alert = alertRepository
                .findByAlertId(alertId)
                .orElseThrow(
                        () -> new IllegalArgumentException(
                                "Alert not found: " + alertId
                        )
                );

        alert.setStatus(status);

        Alert saved = alertRepository.save(alert);

        log.info(
                "SOC_ALERT_STATUS_UPDATED alertId={} status={}",
                saved.getAlertId(),
                saved.getStatus()
        );

        return getAlert(alertId);
    }

    @Transactional(readOnly = true)
    public List<String> getEventIds(String alertId) {

        return alertEventRepository
                .findByAlertId(alertId)
                .stream()
                .map(AlertEvent::getEventId)
                .toList();
    }

    private AlertResponse toResponse(Alert alert) {

        List<String> eventIds =
                getEventIds(alert.getAlertId());

        return new AlertResponse(
                alert.getAlertId(),
                alert.getTimestamp(),
                alert.getRuleName(),
                alert.getSeverity(),
                alert.getStatus(),
                alert.getDescription(),
                alert.getAffectedService(),
                alert.getAffectedUser(),
                alert.getAffectedEntity(),
                alert.getRecommendedAction(),
                eventIds
        );
    }
}