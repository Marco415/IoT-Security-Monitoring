package com.iotsecurity.soc.service;

import com.iotsecurity.soc.model.DetectionRule;
import com.iotsecurity.soc.model.SOCAlert;
import com.iotsecurity.soc.model.SOCEvent;
import com.iotsecurity.soc.model.Severity;
import com.iotsecurity.soc.repository.SOCEventRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;

@Service
public class DetectionEngine {

    private static final Logger log =
            LoggerFactory.getLogger(DetectionEngine.class);

    private static final int FAILED_LOGIN_THRESHOLD = 5;
    private static final int UNAUTHORIZED_THRESHOLD = 5;
    private static final int SERVICE_FAILURE_THRESHOLD = 3;
    private static final int REQUEST_RATE_THRESHOLD = 100;

    private static final int FIVE_MINUTES = 5;
    private static final int ONE_MINUTE = 1;

    private final SOCEventRepository eventRepository;

    public DetectionEngine(
            SOCEventRepository eventRepository
    ) {
        this.eventRepository = eventRepository;
    }

    /**
     * Runs all SOC detection rules against the supplied event.
     *
     * The engine does not create or persist alerts.
     * It only determines which alerts should be generated.
     */
    public List<DetectionResult> analyze(
            SOCEvent event
    ) {

        log.info(
                "Starting SOC event analysis eventId={} serviceName={} " +
                        "eventType={} severity={} userId={} sourceIp={} " +
                        "endpoint={} statusCode={} correlationId={}",
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

        List<DetectionResult> results =
                new ArrayList<>();

        detectMultipleFailedLogins(
                event,
                results
        );

        detectUnauthorizedEndpointAccess(
                event,
                results
        );

        detectServiceFailure(
                event,
                results
        );

        detectAbnormalRequestRate(
                event,
                results
        );

        log.info(
                "Completed SOC event analysis eventId={} " +
                        "eventType={} detectionCount={} correlationId={}",
                event.getEventId(),
                event.getEventType(),
                results.size(),
                event.getCorrelationId()
        );

        return results;
    }


    // ============================================================
    // RULE 1
    // MULTIPLE FAILED LOGINS
    // ============================================================

    private void detectMultipleFailedLogins(
            SOCEvent event,
            List<DetectionResult> results
    ) {

        log.debug(
                "Evaluating detection rule={} eventId={} eventType={} " +
                        "userId={} sourceIp={}",
                DetectionRule.MULTIPLE_FAILED_LOGINS,
                event.getEventId(),
                event.getEventType(),
                event.getUserId(),
                event.getSourceIp()
        );

        if (!"FAILED_LOGIN".equalsIgnoreCase(
                event.getEventType())) {

            return;
        }

        LocalDateTime window =
                event.getTimestamp()
                        .minusMinutes(FIVE_MINUTES);

        boolean alertGenerated = false;

        // --------------------------------------------------------
        // USER
        // --------------------------------------------------------

        if (event.getUserId() != null &&
                !event.getUserId().isBlank()) {

            List<SOCEvent> userEvents =
                    eventRepository
                            .findByUserIdAndTimestampAfter(
                                    event.getUserId(),
                                    window
                            );

            long failedLogins =
                    userEvents.stream()
                            .filter(e ->
                                    "FAILED_LOGIN"
                                            .equalsIgnoreCase(
                                                    e.getEventType()))
                            .count();

            log.info(
                    "Failed login detection user check eventId={} " +
                            "userId={} windowStart={} failedLoginCount={} threshold={}",
                    event.getEventId(),
                    event.getUserId(),
                    window,
                    failedLogins,
                    FAILED_LOGIN_THRESHOLD
            );

            if (failedLogins >= FAILED_LOGIN_THRESHOLD) {

                results.add(
                        new DetectionResult(
                                DetectionRule.MULTIPLE_FAILED_LOGINS,
                                Severity.HIGH,
                                event,
                                (int) failedLogins,
                                "Five or more failed login attempts detected " +
                                        "for the same user within five minutes."
                        )
                );

                alertGenerated = true;
            }
        }

        // --------------------------------------------------------
        // SOURCE IP
        // --------------------------------------------------------

        if (!alertGenerated &&
                event.getSourceIp() != null &&
                !event.getSourceIp().isBlank()) {

            List<SOCEvent> ipEvents =
                    eventRepository
                            .findBySourceIpAndTimestampAfter(
                                    event.getSourceIp(),
                                    window
                            );

            long failedLogins =
                    ipEvents.stream()
                            .filter(e ->
                                    "FAILED_LOGIN"
                                            .equalsIgnoreCase(
                                                    e.getEventType()))
                            .count();

            log.info(
                    "Failed login detection IP check eventId={} " +
                            "sourceIp={} windowStart={} failedLoginCount={} threshold={}",
                    event.getEventId(),
                    event.getSourceIp(),
                    window,
                    failedLogins,
                    FAILED_LOGIN_THRESHOLD
            );

            if (failedLogins >= FAILED_LOGIN_THRESHOLD) {

                results.add(
                        new DetectionResult(
                                DetectionRule.MULTIPLE_FAILED_LOGINS,
                                Severity.HIGH,
                                event,
                                (int) failedLogins,
                                "Five or more failed login attempts detected " +
                                        "from the same source IP within five minutes."
                        )
                );
            }
        }
    }


    // ============================================================
    // RULE 2
    // UNAUTHORIZED ENDPOINT ACCESS
    // ============================================================

    private void detectUnauthorizedEndpointAccess(
            SOCEvent event,
            List<DetectionResult> results
    ) {

        log.debug(
                "Evaluating detection rule={} eventId={} " +
                        "endpoint={} statusCode={} userId={} sourceIp={}",
                DetectionRule.UNAUTHORIZED_ENDPOINT_ACCESS,
                event.getEventId(),
                event.getEndpoint(),
                event.getStatusCode(),
                event.getUserId(),
                event.getSourceIp()
        );

        if (event.getStatusCode() == null) {
            return;
        }

        if (event.getStatusCode() != 401 &&
                event.getStatusCode() != 403) {
            return;
        }

        if (!isProtectedEndpoint(
                event.getEndpoint())) {

            return;
        }

        LocalDateTime window =
                event.getTimestamp()
                        .minusMinutes(FIVE_MINUTES);

        List<SOCEvent> recentEvents;

        if (event.getSourceIp() != null &&
                !event.getSourceIp().isBlank()) {

            recentEvents =
                    eventRepository
                            .findBySourceIpAndTimestampAfter(
                                    event.getSourceIp(),
                                    window
                            );

        } else if (event.getUserId() != null &&
                !event.getUserId().isBlank()) {

            recentEvents =
                    eventRepository
                            .findByUserIdAndTimestampAfter(
                                    event.getUserId(),
                                    window
                            );

        } else {
            return;
        }

        long unauthorizedRequests =
                recentEvents.stream()
                        .filter(this::isUnauthorizedRequest)
                        .count();

        log.info(
                "Unauthorized access detection eventId={} endpoint={} " +
                        "statusCode={} windowStart={} unauthorizedRequestCount={} threshold={}",
                event.getEventId(),
                event.getEndpoint(),
                event.getStatusCode(),
                window,
                unauthorizedRequests,
                UNAUTHORIZED_THRESHOLD
        );

        if (unauthorizedRequests >=
                UNAUTHORIZED_THRESHOLD) {

            Severity severity =
                    isSensitiveEndpoint(
                            event.getEndpoint())
                            ? Severity.HIGH
                            : Severity.MEDIUM;

            results.add(
                    new DetectionResult(
                            DetectionRule.UNAUTHORIZED_ENDPOINT_ACCESS,
                            severity,
                            event,
                            (int) unauthorizedRequests,
                            "Repeated unauthorized access to protected endpoint."
                    )
            );
        }
    }


    // ============================================================
    // RULE 3
    // SERVICE FAILURE
    // ============================================================

    private void detectServiceFailure(
            SOCEvent event,
            List<DetectionResult> results
    ) {

        log.debug(
                "Evaluating detection rule={} eventId={} serviceName={} statusCode={}",
                DetectionRule.SERVICE_FAILURE,
                event.getEventId(),
                event.getServiceName(),
                event.getStatusCode()
        );

        if (event.getStatusCode() == null ||
                event.getStatusCode() != 500) {

            return;
        }

        LocalDateTime window =
                event.getTimestamp()
                        .minusMinutes(FIVE_MINUTES);

        List<SOCEvent> recentEvents =
                eventRepository
                        .findByServiceNameAndTimestampAfter(
                                event.getServiceName(),
                                window
                        );

        long failures =
                recentEvents.stream()
                        .filter(e ->
                                e.getStatusCode() != null &&
                                        e.getStatusCode() == 500)
                        .count();

        log.info(
                "Service failure detection eventId={} serviceName={} " +
                        "windowStart={} failureCount={} threshold={}",
                event.getEventId(),
                event.getServiceName(),
                window,
                failures,
                SERVICE_FAILURE_THRESHOLD
        );

        if (failures >=
                SERVICE_FAILURE_THRESHOLD) {

            results.add(
                    new DetectionResult(
                            DetectionRule.SERVICE_FAILURE,
                            Severity.HIGH,
                            event,
                            (int) failures,
                            "Repeated HTTP 500 errors detected."
                    )
            );
        }
    }


    // ============================================================
    // RULE 4
    // ABNORMAL REQUEST RATE
    // ============================================================

    private void detectAbnormalRequestRate(
            SOCEvent event,
            List<DetectionResult> results
    ) {

        log.debug(
                "Evaluating detection rule={} eventId={} sourceIp={}",
                DetectionRule.ABNORMAL_REQUEST_RATE,
                event.getEventId(),
                event.getSourceIp()
        );

        if (event.getSourceIp() == null ||
                event.getSourceIp().isBlank()) {

            return;
        }

        LocalDateTime window =
                event.getTimestamp()
                        .minusMinutes(ONE_MINUTE);

        List<SOCEvent> recentEvents =
                eventRepository
                        .findBySourceIpAndTimestampAfter(
                                event.getSourceIp(),
                                window
                        );

        long requestCount =
                recentEvents.stream()
                        .filter(this::isHttpRequest)
                        .count();

        log.info(
                "Request rate detection eventId={} sourceIp={} " +
                        "windowStart={} requestCount={} threshold={}",
                event.getEventId(),
                event.getSourceIp(),
                window,
                requestCount,
                REQUEST_RATE_THRESHOLD
        );

        if (requestCount >
                REQUEST_RATE_THRESHOLD) {

            results.add(
                    new DetectionResult(
                            DetectionRule.ABNORMAL_REQUEST_RATE,
                            Severity.HIGH,
                            event,
                            (int) requestCount,
                            "Abnormally high request rate detected. " +
                                    "Possible DoS activity."
                    )
            );
        }
    }


    // ============================================================
    // HELPERS
    // ============================================================

    private boolean isProtectedEndpoint(
            String endpoint
    ) {

        if (endpoint == null) {
            return false;
        }

        return endpoint.startsWith("/api/devices") ||
                endpoint.startsWith("/api/events");
    }


    private boolean isSensitiveEndpoint(
            String endpoint
    ) {

        if (endpoint == null) {
            return false;
        }

        return endpoint.startsWith("/api/devices") ||
                endpoint.startsWith("/api/events");
    }


    private boolean isUnauthorizedRequest(
            SOCEvent event
    ) {

        return event.getStatusCode() != null &&
                (event.getStatusCode() == 401 ||
                        event.getStatusCode() == 403);
    }


    private boolean isHttpRequest(
            SOCEvent event
    ) {

        return event.getHttpMethod() != null &&
                event.getEndpoint() != null;
    }


    // ============================================================
    // DETECTION RESULT
    // ============================================================

    public record DetectionResult(
            DetectionRule rule,
            Severity severity,
            SOCEvent event,
            int eventCount,
            String message
    ) {
    }
}