package com.iotsecurity.event.controller;

import com.iotsecurity.event.dto.AlertResponse;
import com.iotsecurity.event.dto.AlertRequest;
import com.iotsecurity.event.model.AlertStatus;
import com.iotsecurity.event.service.AlertService;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.tags.Tag;

import jakarta.validation.Valid;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;

import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api/alerts")
@Tag(
        name = "SOC Alerts",
        description = "Security alert management endpoints"
)
@SecurityRequirement(name = "bearerAuth")
public class AlertController {

    private static final Logger log =
            LoggerFactory.getLogger(AlertController.class);

    private final AlertService alertService;

    public AlertController(AlertService alertService) {
        this.alertService = alertService;
    }

    @Operation(
            summary = "Create security alert",
            description =
                    "Creates an alert and optionally associates one or more security events."
    )
    @PostMapping
    public ResponseEntity<AlertResponse> createAlert(
            @Valid @RequestBody AlertRequest request
    ) {

        log.info(
                "SOC_ALERT_CREATE_REQUEST ruleName={} severity={} status={} affectedService={} affectedUser={} affectedEntity={}",
                request.getRuleName(),
                request.getSeverity(),
                request.getStatus(),
                request.getAffectedService(),
                request.getAffectedUser(),
                request.getAffectedEntity()
        );

        AlertResponse response =
                alertService.createAlert(request);

        return ResponseEntity
                .status(HttpStatus.CREATED)
                .body(response);
    }

    @Operation(
            summary = "Get all security alerts"
    )
    @GetMapping
    public ResponseEntity<List<AlertResponse>> getAllAlerts() {

        return ResponseEntity.ok(
                alertService.getAllAlerts()
        );
    }

    @Operation(
            summary = "Get alert by ID"
    )
    @GetMapping("/{alertId}")
    public ResponseEntity<AlertResponse> getAlert(
            @Parameter(
                    description = "Unique alert identifier",
                    example = "alert-001"
            )
            @PathVariable String alertId
    ) {

        return ResponseEntity.ok(
                alertService.getAlert(alertId)
        );
    }

    @Operation(
            summary = "Update alert status"
    )
    @PatchMapping("/{alertId}/status")
    public ResponseEntity<AlertResponse> updateStatus(
            @PathVariable String alertId,
            @RequestParam AlertStatus status
    ) {

        log.info(
                "SOC_ALERT_STATUS_REQUEST alertId={} status={}",
                alertId,
                status
        );

        return ResponseEntity.ok(
                alertService.updateStatus(
                        alertId,
                        status
                )
        );
    }

    @Operation(
            summary = "Get events associated with an alert"
    )
    @GetMapping("/{alertId}/events")
    public ResponseEntity<List<String>> getAlertEvents(
            @PathVariable String alertId
    ) {

        return ResponseEntity.ok(
                alertService.getEventIds(alertId)
        );
    }
}