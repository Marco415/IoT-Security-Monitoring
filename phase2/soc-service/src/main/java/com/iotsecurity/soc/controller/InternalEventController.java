package com.iotsecurity.soc.controller;

import com.iotsecurity.soc.dto.EventRequest;
import com.iotsecurity.soc.model.SOCEvent;
import com.iotsecurity.soc.service.AlertService;
import com.iotsecurity.soc.service.EventNormalizationService;
import jakarta.validation.Valid;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/internal/soc/events")
public class InternalEventController {

    private static final Logger log =
            LoggerFactory.getLogger(InternalEventController.class);

    private final EventNormalizationService normalizationService;

    private final AlertService alertService;

    private final String internalApiKey;


    public InternalEventController(
            EventNormalizationService normalizationService,
            AlertService alertService,
            @Value("${soc.internal.api-key:change-this-internal-soc-key}")
            String internalApiKey
    ) {

        this.normalizationService =
                normalizationService;

        this.alertService =
                alertService;

        this.internalApiKey =
                internalApiKey;
    }


    @PostMapping
    public ResponseEntity<SOCEvent> submitInternalEvent(

            @RequestHeader(
                    value = "X-Internal-SOC-Key",
                    required = false
            )
            String providedApiKey,

            @Valid @RequestBody EventRequest request
    ) {

        if (providedApiKey == null ||
                !providedApiKey.equals(internalApiKey)) {

            log.warn(
                    "Rejected internal SOC event submission " +
                            "because API key was invalid"
            );

            return ResponseEntity
                    .status(HttpStatus.UNAUTHORIZED)
                    .build();
        }


        log.info(
                "Received internal SOC event " +
                        "serviceName={} eventType={} " +
                        "statusCode={} endpoint={} sourceIp={} " +
                        "correlationId={}",
                request.serviceName(),
                request.eventType(),
                request.statusCode(),
                request.endpoint(),
                request.sourceIp(),
                request.correlationId()
        );


        SOCEvent event =
                normalizationService.normalize(request);


        /*
         * AlertService now performs the complete processing flow:
         *
         * 1. Run detection.
         * 2. Decide whether the event should be persisted.
         * 3. Persist only relevant events.
         * 4. Synchronize persisted events with Neo4j.
         * 5. Create triggered alerts.
         */
        SOCEvent processedEvent =
                alertService.saveEvent(event);


        log.info(
                "Internal SOC event processed " +
                        "eventId={} eventType={} statusCode={} " +
                        "endpoint={} correlationId={}",
                processedEvent.getEventId(),
                processedEvent.getEventType(),
                processedEvent.getStatusCode(),
                processedEvent.getEndpoint(),
                processedEvent.getCorrelationId()
        );


        return ResponseEntity
                .status(HttpStatus.CREATED)
                .body(processedEvent);
    }
}