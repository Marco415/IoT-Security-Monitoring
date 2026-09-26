package com.iotsecurity.soc.service;

import com.iotsecurity.soc.dto.dashboard.DashboardServiceResponse;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestClient;

import java.util.ArrayList;
import java.util.List;

@Service
public class ServiceHealthService {

    private final RestClient restClient;

    private final String gatewayUrl;
    private final String authUrl;
    private final String deviceUrl;
    private final String eventUrl;

    public ServiceHealthService(
            @Value("${soc.services.gateway-url}") String gatewayUrl,
            @Value("${soc.services.auth-url}") String authUrl,
            @Value("${soc.services.device-url}") String deviceUrl,
            @Value("${soc.services.event-url}") String eventUrl
    ) {

        this.restClient =
                RestClient.builder().build();

        this.gatewayUrl = gatewayUrl;
        this.authUrl = authUrl;
        this.deviceUrl = deviceUrl;
        this.eventUrl = eventUrl;
    }

    public List<DashboardServiceResponse> getServiceHealth() {

        List<DashboardServiceResponse> services =
                new ArrayList<>();

        services.add(
                checkService(
                        "Gateway",
                        gatewayUrl
                )
        );

        services.add(
                checkService(
                        "Auth",
                        authUrl
                )
        );

        services.add(
                checkService(
                        "Device",
                        deviceUrl
                )
        );

        services.add(
                checkService(
                        "Event",
                        eventUrl
                )
        );

        return services;
    }

    private DashboardServiceResponse checkService(
            String name,
            String url
    ) {

        try {

            restClient
                    .get()
                    .uri(url)
                    .retrieve()
                    .toBodilessEntity();

            return new DashboardServiceResponse(
                    name,
                    "UP"
            );

        } catch (Exception exception) {

            return new DashboardServiceResponse(
                    name,
                    "DOWN"
            );
        }
    }
}