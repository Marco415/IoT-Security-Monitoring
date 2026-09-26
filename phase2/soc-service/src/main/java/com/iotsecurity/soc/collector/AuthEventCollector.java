package com.iotsecurity.soc.collector;

import com.iotsecurity.soc.client.AuthServiceClient;
import com.iotsecurity.soc.client.AuthServiceClient.AuthEventResponse;
import com.iotsecurity.soc.dto.EventRequest;
import com.iotsecurity.soc.model.SOCEvent;
import com.iotsecurity.soc.repository.SOCEventRepository;
import com.iotsecurity.soc.service.AlertService;
import com.iotsecurity.soc.service.DetectionEngine;
import com.iotsecurity.soc.service.EventNormalizationService;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

import java.util.List;

@Component
public class AuthEventCollector {

    private static final Logger log =
            LoggerFactory.getLogger(AuthEventCollector.class);

    private static final String SOURCE_SYSTEM =
            "auth-service";

    private final AuthServiceClient authServiceClient;
    private final SOCEventRepository socEventRepository;
    private final EventNormalizationService normalizationService;
    private final AlertService alertService;
    private final DetectionEngine detectionEngine;

    public AuthEventCollector(
            AuthServiceClient authServiceClient,
            SOCEventRepository socEventRepository,
            EventNormalizationService normalizationService,
            AlertService alertService,
            DetectionEngine detectionEngine
    ) {
        this.authServiceClient = authServiceClient;
        this.socEventRepository = socEventRepository;
        this.normalizationService = normalizationService;
        this.alertService = alertService;
        this.detectionEngine = detectionEngine;
    }

    @Scheduled(
            fixedDelayString =
                    "${soc.collector.auth.fixed-delay-ms:5000}"
    )
    public void collectAuthEvents() {

        log.info(
                "Running Auth event collector"
        );

        try {

            List<AuthEventResponse> records =
                    authServiceClient.getAuthEvents();

            log.info(
                    "Auth event collector received {} records",
                    records.size()
            );

            for (AuthEventResponse record : records) {
                processRecord(record);
            }

        } catch (Exception e) {

            log.error(
                    "Auth event collector failed: {}",
                    e.getMessage(),
                    e
            );
        }
    }

    private void processRecord(
            AuthEventResponse record
    ) {

        log.info(
                "Checking Auth event: sourceEventId={}, " +
                        "eventType={}, username={}, result={}",
                record.id(),
                record.eventType(),
                record.username(),
                record.result()
        );

        var existingEvent =
                socEventRepository
                        .findBySourceSystemAndSourceEventId(
                                SOURCE_SYSTEM,
                                record.id()
                        );

        if (existingEvent.isPresent()) {

            log.info(
                    "Auth event already exists in SOC database: " +
                            "sourceEventId={}, socEventId={}",
                    record.id(),
                    existingEvent.get().getEventId()
            );

            return;
        }

        EventRequest request =
                mapToEventRequest(record);

        SOCEvent event =
                normalizationService.normalize(
                        request,
                        SOURCE_SYSTEM,
                        record.id()
                );

        SOCEvent savedEvent =
                alertService.saveEvent(event);

        detectionEngine.analyze(savedEvent);

        log.info(
                "Auth event collected into SOC database: " +
                        "sourceEventId={}, socEventId={}, " +
                        "eventType={}, severity={}, " +
                        "username={}, result={}",
                record.id(),
                savedEvent.getEventId(),
                savedEvent.getEventType(),
                savedEvent.getSeverity(),
                record.username(),
                record.result()
        );
    }

    private EventRequest mapToEventRequest(
            AuthEventResponse record
    ) {

        boolean failedLogin =
                "LOGIN".equalsIgnoreCase(
                        record.eventType()
                )
                        &&
                        "FAILURE".equalsIgnoreCase(
                                record.result()
                        );

        String eventType =
                failedLogin
                        ? "FAILED_LOGIN"
                        : mapEventType(record);

        String severity =
                failedLogin
                        ? "HIGH"
                        : "LOW";

        String message =
                "Authentication event: "
                        + record.eventType()
                        + " / "
                        + record.result();

        return new EventRequest(
                record.timestamp(),
                record.service(),
                eventType,
                severity,
                record.username(),
                record.sourceIp(),
                "/api/auth/login",
                "POST",
                failedLogin ? 401 : 200,
                message,
                SOURCE_SYSTEM
                        + ":auth-event:"
                        + record.id(),
                "user:" + record.username()
        );
    }

    private String mapEventType(
            AuthEventResponse record
    ) {

        if ("REGISTER".equalsIgnoreCase(
                record.eventType()
        )) {
            return "OTHER";
        }

        if ("LOGIN".equalsIgnoreCase(
                record.eventType()
        )
                &&
                "SUCCESS".equalsIgnoreCase(
                        record.result()
                )) {

            return "OTHER";
        }

        return "OTHER";
    }
}