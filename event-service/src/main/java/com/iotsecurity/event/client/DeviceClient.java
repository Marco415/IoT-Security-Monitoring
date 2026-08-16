package com.iotsecurity.event.client;

import com.iotsecurity.event.dto.DeviceResponse;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.RestClient;
import org.springframework.web.client.RestClientException;

@Component
public class DeviceClient {

    private final RestClient restClient;

    public DeviceClient(
            RestClient.Builder restClientBuilder,
            @Value("${client.device-service.url}") String deviceServiceUrl) {

        this.restClient = restClientBuilder
                .baseUrl(deviceServiceUrl)
                .build();
    }

    public DeviceResponse getDevice(String deviceId) {

        try {

            return restClient
                    .get()
                    .uri("/api/devices/{deviceId}", deviceId)
                    .retrieve()
                    .body(DeviceResponse.class);

        } catch (HttpClientErrorException.NotFound exception) {

            throw new IllegalArgumentException(
                    "Device with ID '" + deviceId + "' does not exist."
            );

        } catch (RestClientException exception) {

            throw new DeviceServiceUnavailableException(
                    "Device Service is currently unavailable.",
                    exception
            );
        }
    }
}