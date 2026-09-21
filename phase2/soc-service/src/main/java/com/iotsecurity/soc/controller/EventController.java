package com.iotsecurity.soc.controller;

import com.iotsecurity.soc.dto.EventRequest;
import com.iotsecurity.soc.model.SOCEvent;
import com.iotsecurity.soc.service.AlertService;
import com.iotsecurity.soc.service.DetectionEngine;
import com.iotsecurity.soc.service.EventNormalizationService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/soc/events")
@Tag(
        name = "SOC Events",
        description = "Normalized security event ingestion and analysis"
)
@SecurityRequirement(name = "bearerAuth")
public class EventController {

    private static final Logger log =
            LoggerFactory.getLogger(EventController.class);

    private final EventNormalizationService normalizationService;
    private final AlertService alertService;
    private final DetectionEngine detectionEngine;

    public EventController(
            EventNormalizationService normalizationService,
            AlertService alertService,
            DetectionEngine detectionEngine
    ) {
        this.normalizationService = normalizationService;
        this.alertService = alertService;
        this.detectionEngine = detectionEngine;
    }

    @PostMapping
    @Operation(
            summary = "Submit a security event",
            description =
                    "Creates a normalized SOC security event and analyzes " +
                            "it against the configured detection rules. " +
                            "The detection engine checks for multiple failed " +
                            "logins, repeated unauthorized endpoint access, " +
                            "service failures and abnormal request rates."
    )
    @ApiResponses({
            @ApiResponse(
                    responseCode = "201",
                    description = "Security event created and analyzed successfully"
            ),
            @ApiResponse(
                    responseCode = "400",
                    description = "Invalid event data"
            ),
            @ApiResponse(
                    responseCode = "401",
                    description = "Authentication required"
            ),
            @ApiResponse(
                    responseCode = "403",
                    description = "Access denied"
            )
    })
    public ResponseEntity<SOCEvent> submitEvent(
            @Valid @RequestBody EventRequest request
    ) {

        log.info(
                "Received SOC event submission serviceName={} " +
                        "eventType={} severity={} userId={} sourceIp={} " +
                        "endpoint={} httpMethod={} statusCode={} correlationId={}",
                request.serviceName(),
                request.eventType(),
                request.severity(),
                request.userId(),
                request.sourceIp(),
                request.endpoint(),
                request.httpMethod(),
                request.statusCode(),
                request.correlationId()
        );

        SOCEvent event =
                normalizationService.normalize(request);

        SOCEvent savedEvent =
                alertService.saveEvent(event);

        detectionEngine.analyze(savedEvent);

        log.info(
                "SOC event submission completed eventId={} " +
                        "serviceName={} eventType={} severity={} " +
                        "correlationId={}",
                savedEvent.getEventId(),
                savedEvent.getServiceName(),
                savedEvent.getEventType(),
                savedEvent.getSeverity(),
                savedEvent.getCorrelationId()
        );

        return ResponseEntity
                .status(HttpStatus.CREATED)
                .body(savedEvent);
    }
}