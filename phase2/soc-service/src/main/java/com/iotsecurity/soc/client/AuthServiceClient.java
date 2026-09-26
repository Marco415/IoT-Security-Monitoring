package com.iotsecurity.soc.client;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Component;
import org.springframework.web.client.RestClient;

import java.time.LocalDateTime;
import java.util.List;

@Component
public class AuthServiceClient {

    private static final Logger log =
            LoggerFactory.getLogger(AuthServiceClient.class);

    private final RestClient restClient;
    private final String internalServiceKey;

    public AuthServiceClient(
            @Value("${soc.services.auth-events-url}")
            String authEventsUrl,

            @Value("${soc.services.internal-service-key}")
            String internalServiceKey
    ) {

        this.restClient =
                RestClient.builder()
                        .baseUrl(authEventsUrl)
                        .defaultHeader(
                                HttpHeaders.ACCEPT,
                                MediaType.APPLICATION_JSON_VALUE
                        )
                        .build();

        this.internalServiceKey = internalServiceKey;
    }

    public List<AuthEventResponse> getAuthEvents() {

        log.debug(
                "Requesting authentication events from Auth Service"
        );

        List<AuthEventResponse> response =
                restClient
                        .get()
                        .header(
                                "X-Internal-Service-Key",
                                internalServiceKey
                        )
                        .retrieve()
                        .body(
                                new org.springframework.core.ParameterizedTypeReference<
                                        List<AuthEventResponse>
                                        >() {}
                        );

        if (response == null) {
            return List.of();
        }

        log.info(
                "Auth Service returned {} authentication events",
                response.size()
        );

        return response;
    }

    public record AuthEventResponse(
            Long id,
            String eventType,
            String username,
            String sourceIp,
            LocalDateTime timestamp,
            String result,
            String service
    ) {
    }
}