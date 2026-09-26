package com.iotsecurity.soc.service;

import com.iotsecurity.soc.model.DetectionRule;
import com.iotsecurity.soc.model.SOCAlert;
import com.iotsecurity.soc.model.SOCEvent;
import com.iotsecurity.soc.model.Severity;
import com.iotsecurity.soc.repository.SOCAlertRepository;
import com.iotsecurity.soc.repository.SOCEventRepository;
import com.iotsecurity.soc.service.DetectionEngine;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.util.List;

@Service
public class AlertService {

    private static final Logger log =
            LoggerFactory.getLogger(AlertService.class);

    private final SOCEventRepository eventRepository;

    private final SOCAlertRepository alertRepository;

    private final Neo4jGraphService neo4jGraphService;

    private final DetectionEngine detectionEngine;


    public AlertService(
            SOCEventRepository eventRepository,
            SOCAlertRepository alertRepository,
            Neo4jGraphService neo4jGraphService,
            DetectionEngine detectionEngine
    ) {
        this.eventRepository = eventRepository;
        this.alertRepository = alertRepository;
        this.neo4jGraphService = neo4jGraphService;
        this.detectionEngine = detectionEngine;
    }


    // ============================================================
    // SAVE EVENT
    // ============================================================

    /**
     * Saves a normalized SOC event to PostgreSQL and
     * synchronizes the event with Neo4j.
     */
    public SOCEvent saveEvent(
            SOCEvent event
    ) {

        log.info(
                "Saving normalized SOC event " +
                        "eventId={} serviceName={} " +
                        "eventType={} severity={} userId={} " +
                        "sourceIp={} endpoint={} statusCode={} " +
                        "correlationId={}",
                event.getEventId(),
                event.getServiceName(),
                event.getEventType(),
                event.getSeverity(),
                event.getUserId(),
                event.getSourceIp(),
                event.getEndpoint(),
                event.getStatusCode(),
                event.getCorrelationId()
        );


        // --------------------------------------------------------
        // PostgreSQL
        // --------------------------------------------------------

        SOCEvent savedEvent =
                eventRepository.save(event);


        log.info(
                "SOC event saved successfully " +
                        "eventId={} serviceName={} " +
                        "eventType={} severity={} correlationId={}",
                savedEvent.getEventId(),
                savedEvent.getServiceName(),
                savedEvent.getEventType(),
                savedEvent.getSeverity(),
                savedEvent.getCorrelationId()
        );

        try {

            analyzeEvent(savedEvent);

        } catch (Exception ex) {

            /*
             * Event persistence must not fail because
             * detection failed.
             */
            log.error(
                    "SOC event detection failed " +
                            "eventId={} correlationId={}",
                    savedEvent.getEventId(),
                    savedEvent.getCorrelationId(),
                    ex
            );
        }


        // --------------------------------------------------------
        // Neo4j
        // --------------------------------------------------------

        try {

            neo4jGraphService.synchronizeEvent(

                    savedEvent.getEventId() != null
                            ? savedEvent
                            .getEventId()
                            .toString()
                            : null,

                    savedEvent.getTimestamp() != null
                            ? savedEvent
                            .getTimestamp()
                            .toString()
                            : null,

                    savedEvent.getServiceName(),

                    savedEvent.getEventType(),

                    savedEvent.getSeverity() != null
                            ? savedEvent
                            .getSeverity()
                            .toString()
                            : null,

                    savedEvent.getUserId(),

                    savedEvent.getSourceIp(),

                    savedEvent.getMessage()
            );

        } catch (Exception ex) {

            /*
             * PostgreSQL remains the primary SOC event store.
             *
             * A Neo4j failure must not erase the event.
             */

            log.error(
                    "Failed to synchronize SOC event with Neo4j " +
                            "eventId={} correlationId={}",
                    savedEvent.getEventId(),
                    savedEvent.getCorrelationId(),
                    ex
            );
        }

        return savedEvent;
    }


    // ============================================================
    // SEARCH BY USER
    // ============================================================

    public List<SOCEvent> findEventsByUser(
            String userId,
            LocalDateTime timestamp
    ) {

        log.debug(
                "Searching SOC events by userId={} timestampAfter={}",
                userId,
                timestamp
        );

        List<SOCEvent> events =
                eventRepository
                        .findByUserIdAndTimestampAfter(
                                userId,
                                timestamp
                        );

        log.debug(
                "SOC event search completed " +
                        "userId={} timestampAfter={} resultCount={}",
                userId,
                timestamp,
                events.size()
        );

        return events;
    }


    // ============================================================
    // SEARCH BY IP
    // ============================================================

    public List<SOCEvent> findEventsByIp(
            String sourceIp,
            LocalDateTime timestamp
    ) {

        log.debug(
                "Searching SOC events by sourceIp={} timestampAfter={}",
                sourceIp,
                timestamp
        );

        List<SOCEvent> events =
                eventRepository
                        .findBySourceIpAndTimestampAfter(
                                sourceIp,
                                timestamp
                        );

        log.debug(
                "SOC event search completed " +
                        "sourceIp={} timestampAfter={} resultCount={}",
                sourceIp,
                timestamp,
                events.size()
        );

        return events;
    }


    // ============================================================
    // SEARCH BY SERVICE
    // ============================================================

    public List<SOCEvent> findEventsByService(
            String serviceName,
            LocalDateTime timestamp
    ) {

        log.debug(
                "Searching SOC events by serviceName={} timestampAfter={}",
                serviceName,
                timestamp
        );

        List<SOCEvent> events =
                eventRepository
                        .findByServiceNameAndTimestampAfter(
                                serviceName,
                                timestamp
                        );

        log.debug(
                "SOC event search completed " +
                        "serviceName={} timestampAfter={} resultCount={}",
                serviceName,
                timestamp,
                events.size()
        );

        return events;
    }


    // ============================================================
    // CREATE ALERT
    // ============================================================

    /**
     * Creates a SOC alert in PostgreSQL and synchronizes
     * it to Neo4j.
     */
    public SOCAlert createAlert(
            DetectionRule rule,
            Severity severity,
            SOCEvent event,
            int eventCount,
            String message
    ) {

        log.warn(
                "Creating SOC alert " +
                        "rule={} severity={} eventId={} " +
                        "serviceName={} eventType={} eventCount={} " +
                        "userId={} sourceIp={} correlationId={} message={}",
                rule,
                severity,
                event.getEventId(),
                event.getServiceName(),
                event.getEventType(),
                eventCount,
                event.getUserId(),
                event.getSourceIp(),
                event.getCorrelationId(),
                message
        );


        SOCAlert alert =
                new SOCAlert();

        alert.setRule(rule);

        alert.setSeverity(
                severity
        );

        alert.setTimestamp(
                LocalDateTime.now()
        );

        alert.setUserId(
                event.getUserId()
        );

        alert.setSourceIp(
                event.getSourceIp()
        );

        alert.setServiceName(
                event.getServiceName()
        );

        alert.setEventCount(
                eventCount
        );

        alert.setMessage(
                message
        );


        // --------------------------------------------------------
        // PostgreSQL
        // --------------------------------------------------------

        SOCAlert savedAlert =
                alertRepository.save(alert);


        log.warn(
                "SOC alert created successfully " +
                        "alertId={} rule={} severity={} " +
                        "eventCount={} serviceName={} " +
                        "userId={} sourceIp={}",
                savedAlert.getId(),
                savedAlert.getRule(),
                savedAlert.getSeverity(),
                savedAlert.getEventCount(),
                savedAlert.getServiceName(),
                savedAlert.getUserId(),
                savedAlert.getSourceIp()
        );


        // --------------------------------------------------------
        // Neo4j
        // --------------------------------------------------------

        try {

            neo4jGraphService.synchronizeAlert(

                    savedAlert
                            .getId()
                            .toString(),

                    savedAlert.getTimestamp() != null
                            ? savedAlert
                            .getTimestamp()
                            .toString()
                            : null,

                    savedAlert.getRule() != null
                            ? savedAlert
                            .getRule()
                            .toString()
                            : null,

                    savedAlert.getSeverity() != null
                            ? savedAlert
                            .getSeverity()
                            .toString()
                            : null,

                    savedAlert.getUserId(),

                    savedAlert.getSourceIp(),

                    savedAlert.getServiceName(),

                    savedAlert.getEventCount() != null
                            ? savedAlert.getEventCount()
                            : 0,

                    savedAlert.getMessage(),

                    event.getEventId() != null
                            ? event.getEventId()
                            .toString()
                            : null
            );

        } catch (Exception ex) {

            log.error(
                    "Failed to synchronize SOC alert with Neo4j " +
                            "alertId={} eventId={} correlationId={}",
                    savedAlert.getId(),
                    event.getEventId(),
                    event.getCorrelationId(),
                    ex
            );
        }

        return savedAlert;
    }

    /**
     * Creates an alert from multiple related SOC events.
     *
     * This method is intended for detection rules such as
     * MULTIPLE_FAILED_LOGINS where several events contribute
     * to a single alert.
     */
    public SOCAlert createAlertFromEvents(
            DetectionRule rule,
            Severity severity,
            List<SOCEvent> events,
            String message
    ) {

        if (events == null ||
                events.isEmpty()) {

            throw new IllegalArgumentException(
                    "At least one SOC event is required"
            );
        }


        SOCEvent primaryEvent =
                events.get(0);


        log.warn(
                "Creating multi-event SOC alert " +
                        "rule={} severity={} eventCount={} " +
                        "userId={} sourceIp={} serviceName={} " +
                        "correlationId={} message={}",
                rule,
                severity,
                events.size(),
                primaryEvent.getUserId(),
                primaryEvent.getSourceIp(),
                primaryEvent.getServiceName(),
                primaryEvent.getCorrelationId(),
                message
        );


        // ------------------------------------------------------------
        // PostgreSQL ALERT
        // ------------------------------------------------------------

        SOCAlert alert =
                new SOCAlert();

        alert.setRule(
                rule
        );

        alert.setSeverity(
                severity
        );

        alert.setTimestamp(
                LocalDateTime.now()
        );

        alert.setUserId(
                primaryEvent.getUserId()
        );

        alert.setSourceIp(
                primaryEvent.getSourceIp()
        );

        alert.setServiceName(
                primaryEvent.getServiceName()
        );

        alert.setEventCount(
                events.size()
        );

        alert.setMessage(
                message
        );


        SOCAlert savedAlert =
                alertRepository.save(alert);


        // ------------------------------------------------------------
        // EVENT IDs
        // ------------------------------------------------------------

        List<String> eventIds =
                events.stream()
                        .map(SOCEvent::getEventId)
                        .filter(id -> id != null)
                        .map(Object::toString)
                        .toList();


        // ------------------------------------------------------------
        // NEO4J
        // ------------------------------------------------------------

        try {

            String alertId =
                    savedAlert
                            .getId()
                            .toString();


            String severityName =
                    savedAlert.getSeverity() != null
                            ? savedAlert
                            .getSeverity()
                            .toString()
                            : "HIGH";


            String serviceName =
                    savedAlert.getServiceName() != null
                            ? savedAlert
                            .getServiceName()
                            : "auth-service";


            /*
             * For MULTIPLE_FAILED_LOGINS this creates:
             *
             * User
             *   |
             * TRIGGERED
             *   |
             * Events
             *   |
             * CREATED_ALERT
             *   |
             * Alert
             *   |
             * INDICATES
             *   |
             * T1110 Brute Force
             *   |
             * TARGETS
             *   |
             * auth-service
             */
            if (rule == DetectionRule.MULTIPLE_FAILED_LOGINS) {

                neo4jGraphService.createFailedLoginGraph(
                        primaryEvent.getUserId(),
                        eventIds,
                        alertId,
                        severityName,
                        serviceName
                );

            } else {

                /*
                 * For other detection rules retain the
                 * existing generic alert synchronization.
                 */
                neo4jGraphService.synchronizeAlert(

                        alertId,

                        savedAlert.getTimestamp() != null
                                ? savedAlert
                                .getTimestamp()
                                .toString()
                                : null,

                        savedAlert.getRule() != null
                                ? savedAlert
                                .getRule()
                                .toString()
                                : null,

                        severityName,

                        savedAlert.getUserId(),

                        savedAlert.getSourceIp(),

                        serviceName,

                        events.size(),

                        savedAlert.getMessage(),

                        eventIds.isEmpty()
                                ? null
                                : eventIds.get(0)
                );
            }

        } catch (Exception ex) {

            log.error(
                    "Failed to synchronize multi-event SOC alert " +
                            "with Neo4j alertId={}",
                    savedAlert.getId(),
                    ex
            );
        }


        return savedAlert;
    }

    public long getLastSourceEventId(
            String sourceSystem
    ) {
        return eventRepository
                .findTopBySourceSystemOrderBySourceEventIdDesc(
                        sourceSystem
                )
                .map(event -> {
                    if (event.getSourceEventId() == null) {
                        return 0L;
                    }
                    return event.getSourceEventId();
                })
                .orElse(0L);
    }

    public boolean existsBySource(
            String sourceSystem, Long sourceEventId
    ) {
        return eventRepository.existsBySourceSystemAndSourceEventId(
                sourceSystem,
                sourceEventId
        );
    }

    public void analyzeEvent(
            SOCEvent event
    ) {

        List<DetectionEngine.DetectionResult> detections =
                detectionEngine.analyze(event);

        for (DetectionEngine.DetectionResult detection : detections) {

            createAlert(
                    detection.rule(),
                    detection.severity(),
                    detection.event(),
                    detection.eventCount(),
                    detection.message()
            );
        }
    }
}