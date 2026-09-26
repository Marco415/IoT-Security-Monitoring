package com.iotsecurity.soc.client;

import com.iotsecurity.soc.dto.EventServiceSecurityEventResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Component;
import org.springframework.web.client.RestClient;

import java.util.List;

@Component
public class EventServiceClient {

    private static final Logger log =
            LoggerFactory.getLogger(EventServiceClient.class);

    private final RestClient restClient;

    private final String internalApiKey;

    public EventServiceClient(
            RestClient.Builder restClientBuilder,
            @Value("${soc.services.event-url}")
            String eventServiceUrl,
            @Value("${soc.event-service.internal-api-key}")
            String internalApiKey
    ) {

        /*
         * event-url is configured as:
         *
         * http://event-service:8082/actuator/health
         *
         * The collector endpoint is under the same service, so we
         * construct the base URL from the service host/port rather
         * than using the actuator path.
         */
        String baseUrl = eventServiceUrl
                .replaceFirst("/actuator/health/?$", "");

        this.restClient =
                restClientBuilder
                        .baseUrl(baseUrl)
                        .build();

        this.internalApiKey = internalApiKey;

        log.info(
                "Configured event-service client baseUrl={}",
                baseUrl
        );
    }

    /**
     * Retrieves the next batch of security events from event-service.
     *
     * The SOC service does NOT connect directly to event-db.
     */
    public List<EventServiceSecurityEventResponse> getSecurityEvents(
            long afterId,
            int limit
    ) {

        log.debug(
                "Requesting event-service security events " +
                        "afterId={} limit={}",
                afterId,
                limit
        );

        List<EventServiceSecurityEventResponse> response =
                restClient
                        .get()
                        .uri(uriBuilder ->
                                uriBuilder
                                        .path(
                                                "/api/internal/security-events"
                                        )
                                        .queryParam(
                                                "afterId",
                                                afterId
                                        )
                                        .queryParam(
                                                "limit",
                                                limit
                                        )
                                        .build()
                        )
                        .header(
                                "X-Internal-API-Key",
                                internalApiKey
                        )
                        .header(
                                HttpHeaders.ACCEPT,
                                MediaType.APPLICATION_JSON_VALUE
                        )
                        .retrieve()
                        .body(
                                new ParameterizedTypeReference<
                                        List<EventServiceSecurityEventResponse>
                                        >() {
                                }
                        );

        if (response == null) {
            return List.of();
        }

        log.debug(
                "Received event-service security events " +
                        "afterId={} resultCount={}",
                afterId,
                response.size()
        );

        return response;
    }
}