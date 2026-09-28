package com.iotsecurity.gateway;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpStatusCode;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Component;
import org.springframework.web.reactive.function.client.WebClient;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilter;
import org.springframework.web.server.WebFilterChain;
import reactor.core.publisher.Mono;

import java.time.LocalDateTime;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

@Component
@Order(Ordered.HIGHEST_PRECEDENCE + 10)
public class SecurityAuditFilter implements WebFilter {

    private static final Logger log =
            LoggerFactory.getLogger(SecurityAuditFilter.class);

    private final WebClient webClient;
    private final String socServiceUrl;
    private final String internalApiKey;

    public SecurityAuditFilter(
            WebClient.Builder webClientBuilder,
            @Value("${soc.audit.url:http://localhost:8084}")
            String socServiceUrl,
            @Value("${soc.audit.api-key:change-this-internal-soc-key}")
            String internalApiKey
    ) {
        this.webClient = webClientBuilder.build();
        this.socServiceUrl = socServiceUrl;
        this.internalApiKey = internalApiKey;
    }

    @Override
    public Mono<Void> filter(
            ServerWebExchange exchange,
            WebFilterChain chain
    ) {
        return chain
                .filter(exchange)
                .doOnSuccess(ignored -> auditSecurityResponse(exchange))
                .doOnError(error -> {
                    log.debug(
                            "Gateway request ended with exception; " +
                                    "security audit will inspect response " +
                                    "method={} path={}",
                            exchange.getRequest().getMethod(),
                            exchange.getRequest().getPath()
                    );

                    auditSecurityResponse(exchange);
                });
    }

    private void auditSecurityResponse(ServerWebExchange exchange) {

        HttpStatusCode status = exchange.getResponse().getStatusCode();

        if (status == null) {
            return;
        }

        int statusCode = status.value();

        /*
         * Record completed HTTP requests so the SOC can detect:
         *
         * - unauthorized endpoint access
         * - repeated service failures
         * - abnormal request rates
         */

        String endpoint =
                exchange.getRequest()
                        .getURI()
                        .getPath();

        String method =
                exchange.getRequest()
                        .getMethod()
                        .name();

        String sourceIp =
                determineSourceIp(exchange);

        String correlationIdValue =
                exchange.getRequest()
                        .getHeaders()
                        .getFirst(CorrelationIdFilter.CORRELATION_ID);

        if (correlationIdValue == null ||
                correlationIdValue.isBlank()) {

            correlationIdValue = UUID.randomUUID().toString();
        }

        /*
         * Make the value effectively final so it can safely be
         * referenced from the WebClient lambdas below.
         */
        final String correlationId = correlationIdValue;

        String eventType;

        String severity;

        if (statusCode == 401) {
            eventType = "UNAUTHORIZED_ACCESS";
            severity = "MEDIUM";
        } else if (statusCode == 403) {
            eventType = "FORBIDDEN_ACCESS";
            severity = "HIGH";
        } else if (statusCode >= 500) {
            eventType = "SERVICE_ERROR";
            severity = "HIGH";
        } else {
            eventType = "HTTP_REQUEST";
            severity = "LOW";
        }

        String message;

        if (statusCode == 401) {
            message =
                    "Gateway rejected request because authentication was required or invalid.";
        } else if (statusCode == 403) {
            message =
                    "Gateway rejected request because access to the endpoint was forbidden.";
        } else if (statusCode >= 500) {
            message =
                    "Gateway completed request with a server-side error.";
        } else {
            message =
                    "HTTP request processed by API Gateway.";
        }

        /*
         * HashMap is used instead of Map.of because this event
         * contains more than 10 key/value pairs.
         */
        Map<String, Object> event = new HashMap<>();

        event.put("timestamp", LocalDateTime.now().toString());
        event.put("serviceName", "api-gateway");
        event.put("eventType", eventType);
        event.put("severity", severity);
        event.put("userId", "");
        event.put("sourceIp", sourceIp);
        event.put("endpoint", endpoint);
        event.put("httpMethod", method);
        event.put("statusCode", statusCode);
        event.put("message", message);
        event.put("correlationId", correlationId);
        event.put("affectedEntity", endpoint);

        log.info(
                "Gateway security event detected " +
                        "statusCode={} method={} endpoint={} " +
                        "sourceIp={} correlationId={}",
                statusCode,
                method,
                endpoint,
                sourceIp,
                correlationId
        );

        webClient
                .post()
                .uri(socServiceUrl + "/internal/soc/events")
                .contentType(MediaType.APPLICATION_JSON)
                .header(
                        "X-Internal-SOC-Key",
                        internalApiKey
                )
                .bodyValue(event)
                .retrieve()
                .toBodilessEntity()
                .doOnSuccess(response ->
                        log.info(
                                "Gateway security event sent to SOC " +
                                        "statusCode={} endpoint={} " +
                                        "correlationId={}",
                                statusCode,
                                endpoint,
                                correlationId
                        )
                )
                .doOnError(error ->
                        log.error(
                                "Failed to send Gateway security " +
                                        "event to SOC " +
                                        "statusCode={} endpoint={} " +
                                        "correlationId={}",
                                statusCode,
                                endpoint,
                                correlationId,
                                error
                        )
                )
                .subscribe();
    }

    private String determineSourceIp(
            ServerWebExchange exchange
    ) {

        String forwardedFor =
                exchange.getRequest()
                        .getHeaders()
                        .getFirst("X-Forwarded-For");

        if (forwardedFor != null &&
                !forwardedFor.isBlank()) {

            return forwardedFor
                    .split(",")[0]
                    .trim();
        }

        if (exchange.getRequest().getRemoteAddress() != null &&
                exchange.getRequest()
                        .getRemoteAddress()
                        .getAddress() != null) {

            return exchange.getRequest()
                    .getRemoteAddress()
                    .getAddress()
                    .getHostAddress();
        }

        return "unknown";
    }
}