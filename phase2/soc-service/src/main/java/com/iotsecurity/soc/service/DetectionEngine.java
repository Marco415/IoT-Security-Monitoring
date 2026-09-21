package com.iotsecurity.soc.service;

import com.iotsecurity.soc.model.DetectionRule;
import com.iotsecurity.soc.model.SOCEvent;
import com.iotsecurity.soc.model.Severity;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
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

    private final AlertService alertService;

    public DetectionEngine(AlertService alertService) {
        this.alertService = alertService;
    }

    public void analyze(SOCEvent event) {

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

        detectMultipleFailedLogins(event);

        detectUnauthorizedEndpointAccess(event);

        detectServiceFailure(event);

        detectAbnormalRequestRate(event);

        log.info(
                "Completed SOC event analysis eventId={} eventType={} " +
                        "correlationId={}",
                event.getEventId(),
                event.getEventType(),
                event.getCorrelationId()
        );
    }

    /*
     * RULE 1
     *
     * Five or more failed logins from the same
     * user OR source IP within five minutes.
     */
    private void detectMultipleFailedLogins(SOCEvent event) {

        log.debug(
                "Evaluating detection rule={} eventId={} eventType={} " +
                        "userId={} sourceIp={}",
                DetectionRule.MULTIPLE_FAILED_LOGINS,
                event.getEventId(),
                event.getEventType(),
                event.getUserId(),
                event.getSourceIp()
        );

        if (!"FAILED_LOGIN".equalsIgnoreCase(event.getEventType())) {

            log.debug(
                    "Skipping detection rule={} eventId={} reason=eventTypeMismatch",
                    DetectionRule.MULTIPLE_FAILED_LOGINS,
                    event.getEventId()
            );

            return;
        }

        LocalDateTime window =
                event.getTimestamp().minusMinutes(FIVE_MINUTES);

        boolean alertGenerated = false;

        if (event.getUserId() != null &&
                !event.getUserId().isBlank()) {

            List<SOCEvent> userEvents =
                    alertService.findEventsByUser(
                            event.getUserId(),
                            window
                    );

            long failedLogins = userEvents.stream()
                    .filter(e ->
                            "FAILED_LOGIN".equalsIgnoreCase(
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

                log.warn(
                        "Failed login threshold exceeded eventId={} " +
                                "userId={} failedLoginCount={} threshold={}",
                        event.getEventId(),
                        event.getUserId(),
                        failedLogins,
                        FAILED_LOGIN_THRESHOLD
                );

                alertService.createAlert(
                        DetectionRule.MULTIPLE_FAILED_LOGINS,
                        Severity.HIGH,
                        event,
                        (int) failedLogins,
                        "Five or more failed login attempts detected " +
                                "for the same user within five minutes."
                );

                alertGenerated = true;
            }
        }

        if (!alertGenerated &&
                event.getSourceIp() != null &&
                !event.getSourceIp().isBlank()) {

            List<SOCEvent> ipEvents =
                    alertService.findEventsByIp(
                            event.getSourceIp(),
                            window
                    );

            long failedLogins = ipEvents.stream()
                    .filter(e ->
                            "FAILED_LOGIN".equalsIgnoreCase(
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

                log.warn(
                        "Failed login threshold exceeded eventId={} " +
                                "sourceIp={} failedLoginCount={} threshold={}",
                        event.getEventId(),
                        event.getSourceIp(),
                        failedLogins,
                        FAILED_LOGIN_THRESHOLD
                );

                alertService.createAlert(
                        DetectionRule.MULTIPLE_FAILED_LOGINS,
                        Severity.HIGH,
                        event,
                        (int) failedLogins,
                        "Five or more failed login attempts detected " +
                                "from the same source IP within five minutes."
                );
            }
        }
    }

    /*
     * RULE 2
     *
     * Five or more 401/403 responses from the same
     * user OR IP within five minutes.
     */
    private void detectUnauthorizedEndpointAccess(SOCEvent event) {

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

        if (!isProtectedEndpoint(event.getEndpoint())) {

            log.debug(
                    "Skipping unauthorized access detection eventId={} " +
                            "reason=unprotectedEndpoint endpoint={}",
                    event.getEventId(),
                    event.getEndpoint()
            );

            return;
        }

        LocalDateTime window =
                event.getTimestamp().minusMinutes(FIVE_MINUTES);

        List<SOCEvent> recentEvents;

        if (event.getSourceIp() != null &&
                !event.getSourceIp().isBlank()) {

            recentEvents =
                    alertService.findEventsByIp(
                            event.getSourceIp(),
                            window
                    );

        } else if (event.getUserId() != null &&
                !event.getUserId().isBlank()) {

            recentEvents =
                    alertService.findEventsByUser(
                            event.getUserId(),
                            window
                    );

        } else {
            return;
        }

        long unauthorizedRequests = recentEvents.stream()
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

        if (unauthorizedRequests >= UNAUTHORIZED_THRESHOLD) {

            Severity severity =
                    isSensitiveEndpoint(event.getEndpoint())
                            ? Severity.HIGH
                            : Severity.MEDIUM;

            log.warn(
                    "Unauthorized access threshold exceeded eventId={} " +
                            "endpoint={} unauthorizedRequestCount={} " +
                            "threshold={} severity={}",
                    event.getEventId(),
                    event.getEndpoint(),
                    unauthorizedRequests,
                    UNAUTHORIZED_THRESHOLD,
                    severity
            );

            alertService.createAlert(
                    DetectionRule.UNAUTHORIZED_ENDPOINT_ACCESS,
                    severity,
                    event,
                    (int) unauthorizedRequests,
                    "Repeated unauthorized access to protected endpoint."
            );
        }
    }

    /*
     * RULE 3
     *
     * Three or more HTTP 500 responses from the
     * same service within five minutes.
     */
    private void detectServiceFailure(SOCEvent event) {

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
                event.getTimestamp().minusMinutes(FIVE_MINUTES);

        List<SOCEvent> recentEvents =
                alertService.findEventsByService(
                        event.getServiceName(),
                        window
                );

        long failures = recentEvents.stream()
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

        if (failures >= SERVICE_FAILURE_THRESHOLD) {

            log.warn(
                    "Service failure threshold exceeded eventId={} " +
                            "serviceName={} failureCount={} threshold={}",
                    event.getEventId(),
                    event.getServiceName(),
                    failures,
                    SERVICE_FAILURE_THRESHOLD
            );

            alertService.createAlert(
                    DetectionRule.SERVICE_FAILURE,
                    Severity.HIGH,
                    event,
                    (int) failures,
                    "Repeated HTTP 500 errors detected."
            );
        }
    }

    /*
     * RULE 4
     *
     * More than 100 requests from the same IP
     * within 60 seconds.
     */
    private void detectAbnormalRequestRate(SOCEvent event) {

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
                event.getTimestamp().minusMinutes(ONE_MINUTE);

        List<SOCEvent> recentEvents =
                alertService.findEventsByIp(
                        event.getSourceIp(),
                        window
                );

        long requestCount = recentEvents.stream()
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

        if (requestCount > REQUEST_RATE_THRESHOLD) {

            log.warn(
                    "Abnormal request rate threshold exceeded eventId={} " +
                            "sourceIp={} requestCount={} threshold={}",
                    event.getEventId(),
                    event.getSourceIp(),
                    requestCount,
                    REQUEST_RATE_THRESHOLD
            );

            alertService.createAlert(
                    DetectionRule.ABNORMAL_REQUEST_RATE,
                    Severity.HIGH,
                    event,
                    (int) requestCount,
                    "Abnormally high request rate detected. Possible DoS activity."
            );
        }
    }

    private boolean isProtectedEndpoint(String endpoint) {

        if (endpoint == null) {
            return false;
        }

        return endpoint.startsWith("/api/devices") ||
                endpoint.startsWith("/api/events");
    }

    private boolean isSensitiveEndpoint(String endpoint) {

        if (endpoint == null) {
            return false;
        }

        return endpoint.startsWith("/api/devices") ||
                endpoint.startsWith("/api/events");
    }

    private boolean isUnauthorizedRequest(SOCEvent event) {

        return event.getStatusCode() != null &&
                (event.getStatusCode() == 401 ||
                        event.getStatusCode() == 403);
    }

    private boolean isHttpRequest(SOCEvent event) {

        return event.getHttpMethod() != null &&
                event.getEndpoint() != null;
    }
}