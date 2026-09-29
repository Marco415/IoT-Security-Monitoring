package com.iotsecurity.soc.service;

import com.iotsecurity.soc.model.DetectionRule;
import com.iotsecurity.soc.model.SOCEvent;
import com.iotsecurity.soc.model.Severity;
import com.iotsecurity.soc.repository.SOCEventRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.time.LocalDateTime;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Deque;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

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

    /*
     * Stores timestamps of ALL API requests in memory.
     *
     * This is deliberately NOT the SOC database.
     *
     * It allows ABNORMAL_REQUEST_RATE to see normal requests
     * without creating SOCEvent database records for every request.
     *
     * Key:
     *     source IP
     *
     * Value:
     *     timestamps of requests received from that IP
     */
    private final Map<String, Deque<Instant>> requestRateWindows =
            new ConcurrentHashMap<>();

    /*
     * Tracks whether an abnormal-rate alert has already been
     * generated for an IP during the current burst.
     *
     * This prevents:
     *
     * 101 requests -> alert
     * 102 requests -> alert
     * 103 requests -> alert
     *
     * Instead:
     *
     * 101 requests -> alert
     * 102+          -> no duplicate alert
     *
     * Once the request rate drops back to <= 100, the IP is
     * allowed to trigger another alert later.
     */
    private final Map<String, Boolean> requestRateAlertActive =
            new ConcurrentHashMap<>();

    public DetectionEngine(
            SOCEventRepository eventRepository
    ) {
        this.eventRepository = eventRepository;
    }


    // ============================================================
    // MAIN ANALYSIS
    // ============================================================

    /**
     * Runs all SOC detection rules against the supplied event.
     *
     * IMPORTANT:
     *
     * The current event does NOT need to be saved before this
     * method is called.
     *
     * This allows normal HTTP requests to be analyzed without
     * storing them permanently.
     *
     * The returned DetectionResult list tells the caller whether
     * the event triggered an alert.
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

            long previousFailedLogins =
                    userEvents.stream()
                            .filter(e ->
                                    "FAILED_LOGIN"
                                            .equalsIgnoreCase(
                                                    e.getEventType()))
                            .count();

            /*
             * The current event has not necessarily been saved yet.
             *
             * Therefore add 1 for the current failed login.
             */
            long failedLogins =
                    previousFailedLogins + 1;

            log.info(
                    "Failed login detection user check eventId={} " +
                            "userId={} windowStart={} previousFailedLoginCount={} " +
                            "currentFailedLoginCount={} threshold={}",
                    event.getEventId(),
                    event.getUserId(),
                    window,
                    previousFailedLogins,
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

            long previousFailedLogins =
                    ipEvents.stream()
                            .filter(e ->
                                    "FAILED_LOGIN"
                                            .equalsIgnoreCase(
                                                    e.getEventType()))
                            .count();

            /*
             * Include the current failed login because it has not
             * necessarily been persisted yet.
             */
            long failedLogins =
                    previousFailedLogins + 1;

            log.info(
                    "Failed login detection IP check eventId={} " +
                            "sourceIp={} windowStart={} previousFailedLoginCount={} " +
                            "currentFailedLoginCount={} threshold={}",
                    event.getEventId(),
                    event.getSourceIp(),
                    window,
                    previousFailedLogins,
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

        long previousUnauthorizedRequests =
                recentEvents.stream()
                        .filter(this::isUnauthorizedRequest)
                        .count();

        /*
         * Include the current 401/403 event because the current
         * event may not have been persisted yet.
         */
        long unauthorizedRequests =
                previousUnauthorizedRequests + 1;

        log.info(
                "Unauthorized access detection eventId={} endpoint={} " +
                        "statusCode={} windowStart={} previousUnauthorizedRequestCount={} " +
                        "currentUnauthorizedRequestCount={} threshold={}",
                event.getEventId(),
                event.getEndpoint(),
                event.getStatusCode(),
                window,
                previousUnauthorizedRequests,
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
                event.getStatusCode() < 500) {

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

        long previousFailures =
                recentEvents.stream()
                        .filter(e ->
                                e.getStatusCode() != null &&
                                        e.getStatusCode() >= 500)
                        .count();

        /*
         * Include current service failure.
         */
        long failures =
                previousFailures + 1;

        log.info(
                "Service failure detection eventId={} serviceName={} " +
                        "windowStart={} previousFailureCount={} " +
                        "currentFailureCount={} threshold={}",
                event.getEventId(),
                event.getServiceName(),
                window,
                previousFailures,
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
                            "Repeated HTTP 500+ errors detected."
                    )
            );
        }
    }


    // ============================================================
    // RULE 4
    // ABNORMAL REQUEST RATE
    // ============================================================

    /**
     * Detects excessive API request rates WITHOUT querying or
     * storing normal HTTP requests in PostgreSQL.
     *
     * Every request is placed into a short-lived in-memory
     * timestamp window.
     *
     * Example:
     *
     * 1   -> transient only
     * 2   -> transient only
     * ...
     * 100 -> transient only
     * 101 -> ALERT + current event is persisted
     * 102 -> transient only
     * 103 -> transient only
     *
     * This dramatically reduces SOC database and Neo4j growth.
     */
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

        /*
         * Only count actual HTTP/API requests.
         */
        if (!isHttpRequest(event)) {
            return;
        }

        String sourceIp =
                event.getSourceIp();

        Instant now =
                event.getTimestamp()
                        .atZone(
                                java.time.ZoneId.systemDefault()
                        )
                        .toInstant();

        Deque<Instant> timestamps =
                requestRateWindows.computeIfAbsent(
                        sourceIp,
                        key -> new ArrayDeque<>()
                );

        synchronized (timestamps) {

            Instant cutoff =
                    now.minusSeconds(
                            ONE_MINUTE * 60L
                    );

            /*
             * Remove requests older than one minute.
             */
            while (!timestamps.isEmpty()
                    && timestamps.peekFirst()
                    .isBefore(cutoff)) {

                timestamps.removeFirst();
            }

            int previousRequestCount =
                    timestamps.size();

            /*
             * Add CURRENT request.
             *
             * It has not been persisted yet.
             */
            timestamps.addLast(now);

            int requestCount =
                    timestamps.size();

            boolean alertAlreadyActive =
                    requestRateAlertActive.getOrDefault(
                            sourceIp,
                            false
                    );

            log.info(
                    "Request rate detection eventId={} sourceIp={} " +
                            "previousRequestCount={} currentRequestCount={} threshold={} " +
                            "alertAlreadyActive={}",
                    event.getEventId(),
                    sourceIp,
                    previousRequestCount,
                    requestCount,
                    REQUEST_RATE_THRESHOLD,
                    alertAlreadyActive
            );

            /*
             * Trigger ONLY when crossing the threshold.
             *
             * 100 -> no alert
             * 101 -> alert
             * 102 -> no duplicate alert
             * 103 -> no duplicate alert
             */
            if (previousRequestCount <=
                    REQUEST_RATE_THRESHOLD
                    && requestCount >
                    REQUEST_RATE_THRESHOLD
                    && !alertAlreadyActive) {

                requestRateAlertActive.put(
                        sourceIp,
                        true
                );

                results.add(
                        new DetectionResult(
                                DetectionRule.ABNORMAL_REQUEST_RATE,
                                Severity.HIGH,
                                event,
                                requestCount,
                                "Abnormally high request rate detected. " +
                                        "Possible DoS activity."
                        )
                );

                log.warn(
                        "ABNORMAL REQUEST RATE DETECTED " +
                                "eventId={} sourceIp={} requestCount={} threshold={}",
                        event.getEventId(),
                        sourceIp,
                        requestCount,
                        REQUEST_RATE_THRESHOLD
                );

                return;
            }

            /*
             * If the rolling window has fallen back to <=100,
             * allow another future burst to generate an alert.
             */
            if (requestCount <=
                    REQUEST_RATE_THRESHOLD) {

                requestRateAlertActive.remove(
                        sourceIp
                );
            }
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


    /**
     * Determines whether the event represents an HTTP request.
     *
     * We intentionally do NOT check eventType here.
     *
     * 401 / 403 / 500+ requests are still real HTTP requests
     * and should contribute to request-rate detection.
     */
    private boolean isHttpRequest(
            SOCEvent event
    ) {

        return event.getHttpMethod() != null &&
                !event.getHttpMethod().isBlank() &&
                event.getEndpoint() != null &&
                !event.getEndpoint().isBlank();
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