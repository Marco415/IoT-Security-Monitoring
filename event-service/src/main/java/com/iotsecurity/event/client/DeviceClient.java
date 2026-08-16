package com.iotsecurity.event.client;

import com.iotsecurity.event.dto.DeviceResponse;
import io.github.resilience4j.circuitbreaker.CircuitBreaker;
import io.github.resilience4j.circuitbreaker.CircuitBreakerRegistry;
import io.github.resilience4j.retry.Retry;
import io.github.resilience4j.retry.RetryRegistry;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.slf4j.MDC;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Component;
import org.springframework.web.client.RestClient;

import java.util.function.Supplier;

@Component
public class DeviceClient {

    private static final Logger log =
            LoggerFactory.getLogger(DeviceClient.class);

    private static final String CORRELATION_ID =
            "X-Correlation-ID";

    private final RestClient restClient;

    private final Retry retry;

    private final CircuitBreaker circuitBreaker;

    public DeviceClient(
            RestClient restClient,
            RetryRegistry retryRegistry,
            CircuitBreakerRegistry circuitBreakerRegistry) {

        this.restClient = restClient;

        this.retry =
                retryRegistry.retry("deviceServiceRetry");

        this.circuitBreaker =
                circuitBreakerRegistry.circuitBreaker(
                        "deviceServiceCircuitBreaker");
    }

    public DeviceResponse getDevice(Long deviceId) {

        String correlationId =
                MDC.get(CORRELATION_ID);

        log.info(
                "Requesting device information deviceId={} correlationId={}",
                deviceId,
                correlationId
        );

        Supplier<DeviceResponse> request = () -> {

            ResponseEntity<DeviceResponse> response =
                    restClient
                            .get()
                            .uri(
                                    "/api/devices/{id}",
                                    deviceId
                            )
                            .header(
                                    CORRELATION_ID,
                                    correlationId != null
                                            ? correlationId
                                            : ""
                            )
                            .retrieve()
                            .toEntity(DeviceResponse.class);

            if (!response.getStatusCode().is2xxSuccessful()
                    || response.getBody() == null) {

                throw new DeviceServiceUnavailableException(
                        "Device service returned an invalid response"
                );
            }

            return response.getBody();
        };

        Supplier<DeviceResponse> retrySupplier =
                Retry.decorateSupplier(
                        retry,
                        request
                );

        Supplier<DeviceResponse> protectedSupplier =
                CircuitBreaker.decorateSupplier(
                        circuitBreaker,
                        retrySupplier
                );

        try {

            return protectedSupplier.get();

        } catch (Exception exception) {

            log.error(
                    "Device service request failed deviceId={} correlationId={}",
                    deviceId,
                    correlationId,
                    exception
            );

            throw new DeviceServiceUnavailableException(
                    "Device service is unavailable",
                    exception
            );
        }
    }
}