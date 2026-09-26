package com.iotsecurity.soc.service;

import com.iotsecurity.soc.dto.EventRequest;
import com.iotsecurity.soc.dto.EventServiceSecurityEventResponse;
import com.iotsecurity.soc.model.SOCEvent;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.util.UUID;

@Service
public class EventNormalizationService {

    private static final Logger log =
            LoggerFactory.getLogger(EventNormalizationService.class);


    public SOCEvent normalize(EventRequest request) {

        log.info(
                "Normalizing incoming SOC event " +
                        "serviceName={} eventType={} severity={} " +
                        "userId={} sourceIp={} endpoint={} " +
                        "httpMethod={} statusCode={} correlationId={}",
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

        LocalDateTime timestamp =
                request.timestamp() != null
                        ? request.timestamp()
                        : LocalDateTime.now();

        if (request.timestamp() == null) {
            log.debug(
                    "SOC event timestamp not supplied; using current timestamp"
            );
        }

        SOCEvent event = new SOCEvent(
                UUID.randomUUID(),
                timestamp,
                request.serviceName(),
                request.eventType(),
                request.severity(),
                request.userId(),
                request.sourceIp(),
                request.endpoint(),
                request.httpMethod(),
                request.statusCode(),
                request.message(),
                request.correlationId(),
                request.affectedEntity()
        );

        log.info(
                "SOC event normalized " +
                        "eventId={} timestamp={} serviceName={} " +
                        "eventType={} severity={} correlationId={}",
                event.getEventId(),
                event.getTimestamp(),
                event.getServiceName(),
                event.getEventType(),
                event.getSeverity(),
                event.getCorrelationId()
        );

        return event;
    }


    public SOCEvent normalize(
            EventRequest request,
            String sourceSystem,
            Long sourceEventId
    ) {

        LocalDateTime timestamp =
                request.timestamp() != null
                        ? request.timestamp()
                        : LocalDateTime.now();

        SOCEvent event = new SOCEvent(
                UUID.randomUUID(),
                timestamp,
                request.serviceName(),
                request.eventType(),
                request.severity(),
                request.userId(),
                request.sourceIp(),
                request.endpoint(),
                request.httpMethod(),
                request.statusCode(),
                request.message(),
                request.correlationId(),
                request.affectedEntity()
        );

        event.setSourceSystem(sourceSystem);
        event.setSourceEventId(sourceEventId);

        log.info(
                "Normalized SOC event " +
                        "eventId={} sourceSystem={} sourceEventId={} " +
                        "eventType={} severity={} userId={} " +
                        "sourceIp={} correlationId={}",
                event.getEventId(),
                sourceSystem,
                sourceEventId,
                event.getEventType(),
                event.getSeverity(),
                event.getUserId(),
                event.getSourceIp(),
                event.getCorrelationId()
        );

        return event;
    }


    /**
     * Converts an event-service SecurityEvent into the
     * SOC normalized event model.
     *
     * Important:
     * - event-service owns its own database
     * - SOC does not access event-db directly
     * - sourceEventId stores the event-service DB row ID
     * - eventId is generated independently by SOC
     */
    public SOCEvent normalizeEventServiceEvent(
            EventServiceSecurityEventResponse sourceEvent
    ) {

        if (sourceEvent == null) {
            throw new IllegalArgumentException(
                    "Event-service source event must not be null"
            );
        }

        if (sourceEvent.getId() == null) {
            throw new IllegalArgumentException(
                    "Event-service source event ID must not be null"
            );
        }

        SOCEvent event = new SOCEvent();

        /*
         * SOC-owned identity.
         */
        event.setEventId(
                UUID.randomUUID()
        );

        /*
         * Source tracking.
         *
         * This does NOT create a database relationship to event-db.
         * It simply records where this SOC event originated.
         */
        event.setSourceSystem(
                "event-service"
        );

        event.setSourceEventId(
                sourceEvent.getId()
        );

        /*
         * Timestamp.
         */
        event.setTimestamp(
                sourceEvent.getTimestamp() != null
                        ? sourceEvent.getTimestamp()
                        : LocalDateTime.now()
        );

        /*
         * Originating service.
         */
        event.setServiceName(
                "event-service"
        );

        /*
         * Event data.
         */
        event.setEventType(
                sourceEvent.getEventType()
        );

        /*
         * SOCEvent expects severity as String.
         *
         * Do not convert this to the SOC Severity enum here.
         */
        event.setSeverity(
                normalizeSeverity(
                        sourceEvent.getSeverity()
                )
        );

        /*
         * event-service security_events currently does not
         * contain a user ID.
         */
        event.setUserId(
                null
        );

        event.setSourceIp(
                sourceEvent.getSourceIp()
        );

        /*
         * Not supplied by event-service SecurityEvent.
         */
        event.setEndpoint(
                null
        );

        event.setHttpMethod(
                null
        );

        event.setStatusCode(
                null
        );

        /*
         * SecurityEvent.description becomes the SOC message.
         */
        event.setMessage(
                sourceEvent.getDescription()
        );

        /*
         * Deterministic correlation ID.
         *
         * Repeated collection attempts for the same source
         * record therefore produce the same correlation ID.
         */
        event.setCorrelationId(
                "event-service:security-event:"
                        + sourceEvent.getId()
        );

        /*
         * SOCEvent expects affectedEntity as String.
         *
         * The UUID is converted to its textual representation.
         */
        event.setAffectedEntity(
                sourceEvent.getDeviceId()
        );

        log.info(
                "Normalized event-service event " +
                        "eventId={} sourceSystem={} sourceEventId={} " +
                        "eventType={} severity={} sourceIp={} " +
                        "affectedEntity={} correlationId={}",
                event.getEventId(),
                event.getSourceSystem(),
                event.getSourceEventId(),
                event.getEventType(),
                event.getSeverity(),
                event.getSourceIp(),
                event.getAffectedEntity(),
                event.getCorrelationId()
        );

        return event;
    }


    /**
     * Normalizes severity to the string representation expected
     * by SOCEvent.
     */
    private String normalizeSeverity(
            String severity
    ) {

        if (severity == null ||
                severity.isBlank()) {

            log.debug(
                    "Event-service severity missing; defaulting to MEDIUM"
            );

            return "MEDIUM";
        }

        String normalized =
                severity.trim().toUpperCase();

        /*
         * Keep the SOC severity representation consistent.
         */
        switch (normalized) {

            case "LOW":
            case "MEDIUM":
            case "HIGH":
            case "CRITICAL":

                return normalized;

            default:

                log.warn(
                        "Unknown event-service severity={} " +
                                "defaultingTo=MEDIUM",
                        severity
                );

                return "MEDIUM";
        }
    }
}