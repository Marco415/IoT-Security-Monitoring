package com.iotsecurity.soc.collector;

import com.iotsecurity.soc.client.EventServiceClient;
import com.iotsecurity.soc.dto.EventServiceSecurityEventResponse;
import com.iotsecurity.soc.model.SOCEvent;
import com.iotsecurity.soc.service.AlertService;
import com.iotsecurity.soc.service.EventNormalizationService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

import java.util.List;

@Component
public class EventSecurityEventCollector {

    private static final Logger log =
            LoggerFactory.getLogger(
                    EventSecurityEventCollector.class
            );

    private static final String SOURCE_SYSTEM = "event-service";

    private final EventServiceClient eventServiceClient;
    private final EventNormalizationService normalizationService;
    private final AlertService alertService;
    private final int batchSize;

    @Value("${soc.collector.event-service.enabled:true}")
    private boolean enabled;

    public EventSecurityEventCollector(
            EventServiceClient eventServiceClient,
            EventNormalizationService normalizationService,
            AlertService alertService,
            @Value("${soc.collector.event-service.batch-size:100}")
            int batchSize
    ) {
        this.eventServiceClient = eventServiceClient;
        this.normalizationService = normalizationService;
        this.alertService = alertService;
        this.batchSize = Math.min(
                Math.max(batchSize, 1),
                500
        );
    }

    @Scheduled(
            fixedDelayString =
                    "${soc.collector.event-service.poll-interval-ms:10000}"
    )
    public void collectEvents() {

        if (!enabled) {
            log.warn(
                    "Event-service SOC collector disabled"
            );
            return;
        }

        final String sourceSystem = "event-service";

        try {

            long lastSourceEventId =
                    alertService.getLastSourceEventId(
                            SOURCE_SYSTEM
                    );

            log.info(
                    "Starting event-service SOC collection " +
                            "sourceSystem={} lastSourceEventId={} " +
                            "batchSize={}",
                    SOURCE_SYSTEM,
                    lastSourceEventId,
                    batchSize
            );

            List<EventServiceSecurityEventResponse> events =
                    eventServiceClient.getSecurityEvents(
                            lastSourceEventId,
                            batchSize
                    );

            if (events.isEmpty()) {

                log.info(
                        "No new event-service security events " +
                                "sourceSystem={} lastSourceEventId={}",
                        sourceSystem,
                        lastSourceEventId
                );

                return;
            }

            for (
                    EventServiceSecurityEventResponse sourceEvent :
                    events
            ) {
                processEvent(sourceEvent);
            }

            log.info(
                    "Event-service SOC collection completed " +
                            "sourceSystem={} collectedCount={} " +
                            "previousLastSourceEventId={} " +
                            "newLastSourceEventId={}",
                    sourceSystem,
                    events.size(),
                    lastSourceEventId,
                    events.get(events.size() - 1).getId()
            );

        } catch (Exception ex) {

            log.error(
                    "Event-service SOC collection failed " +
                            "sourceSystem={} batchSize={}",
                    sourceSystem,
                    batchSize,
                    ex
            );
        }
    }

    private void processEvent(
            EventServiceSecurityEventResponse sourceEvent
    ) {

        if (
                sourceEvent == null ||
                        sourceEvent.getId() == null
        ) {

            log.warn(
                    "Skipping invalid event-service event " +
                            "reason=missingSourceId"
            );

            return;
        }

        log.info(
                "Collected event-service security event " +
                        "sourceEventId={} eventId={} eventType={} " +
                        "severity={} status={} sourceIp={}",
                sourceEvent.getId(),
                sourceEvent.getEventId(),
                sourceEvent.getEventType(),
                sourceEvent.getSeverity(),
                sourceEvent.getStatus(),
                sourceEvent.getSourceIp()
        );

        if (
                alertService.existsBySource(
                        SOURCE_SYSTEM,
                        sourceEvent.getId()
                )
        ) {

            log.info(
                    "Skipping already-ingested event-service event " +
                            "sourceEventId={}",
                    sourceEvent.getId()
            );

            return;
        }

        SOCEvent normalizedEvent =
                normalizationService
                        .normalizeEventServiceEvent(
                                sourceEvent
                        );

        SOCEvent savedEvent =
                alertService.saveEvent(
                        normalizedEvent
                );

        alertService.analyzeEvent(
                savedEvent
        );

        log.info(
                "Event-service security event ingested successfully " +
                        "sourceEventId={} socEventId={} " +
                        "eventType={} severity={} correlationId={}",
                sourceEvent.getId(),
                savedEvent.getEventId(),
                savedEvent.getEventType(),
                savedEvent.getSeverity(),
                savedEvent.getCorrelationId()
        );
    }
}