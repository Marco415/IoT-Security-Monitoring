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

        this.retry = retryRegistry.retry(
                "deviceServiceRetry"
        );

        this.circuitBreaker =
                circuitBreakerRegistry.circuitBreaker(
                        "deviceServiceCircuitBreaker"
                );
    }

    /**
     * Retrieve a device from the Device Service.
     *
     * The Event Service can receive either:
     *
     * 1. The Device database ID
     *    Example: 1
     *
     * 2. The actual device_id
     *    Example: DEV-001
     *
     * Numeric values are treated as database IDs.
     * Non-numeric values are treated as device_id values.
     */
    public DeviceResponse getDevice(String deviceIdentifier) {

        String correlationId =
                MDC.get(CORRELATION_ID);

        log.info(
                "Requesting device information identifier={} correlationId={}",
                deviceIdentifier,
                correlationId
        );

        Supplier<DeviceResponse> request = () -> {

            log.debug(
                    "Calling Device Service for identifier={}",
                    deviceIdentifier
            );

            ResponseEntity<DeviceResponse> response;

            /*
             * The client currently sends the database ID from
             * the device dropdown.
             *
             * Example:
             *
             *     1
             *
             * Therefore use:
             *
             *     GET /api/devices/1
             *
             * If the identifier is something such as:
             *
             *     DEV-001
             *
             * use:
             *
             *     GET /api/devices/device-id/DEV-001
             */
            if (isDatabaseId(deviceIdentifier)) {

                Long databaseId =
                        Long.valueOf(deviceIdentifier);

                log.debug(
                        "Using Device Service database-ID endpoint databaseId={}",
                        databaseId
                );

                response =
                        restClient
                                .get()
                                .uri(
                                        "/api/devices/{id}",
                                        databaseId
                                )
                                .header(
                                        CORRELATION_ID,
                                        correlationId != null
                                                ? correlationId
                                                : ""
                                )
                                .retrieve()
                                .toEntity(
                                        DeviceResponse.class
                                );

            } else {

                log.debug(
                        "Using Device Service device-ID endpoint deviceId={}",
                        deviceIdentifier
                );

                response =
                        restClient
                                .get()
                                .uri(
                                        "/api/devices/device-id/{deviceId}",
                                        deviceIdentifier
                                )
                                .header(
                                        CORRELATION_ID,
                                        correlationId != null
                                                ? correlationId
                                                : ""
                                )
                                .retrieve()
                                .toEntity(
                                        DeviceResponse.class
                                );
            }

            if (!response.getStatusCode().is2xxSuccessful()) {

                log.warn(
                        "Device Service returned status={} identifier={}",
                        response.getStatusCode(),
                        deviceIdentifier
                );

                throw new DeviceServiceUnavailableException(
                        "Device service returned HTTP status "
                                + response.getStatusCode()
                );
            }

            if (response.getBody() == null) {

                log.warn(
                        "Device Service returned an empty response identifier={}",
                        deviceIdentifier
                );

                throw new DeviceServiceUnavailableException(
                        "Device service returned an empty response"
                );
            }

            DeviceResponse device =
                    response.getBody();

            log.info(
                    "Device information successfully retrieved " +
                            "databaseId={} deviceId={} correlationId={}",
                    device.id(),
                    device.deviceId(),
                    correlationId
            );

            return device;
        };

        /*
         * Retry temporary communication failures.
         */
        Supplier<DeviceResponse> retrySupplier =
                Retry.decorateSupplier(
                        retry,
                        request
                );

        /*
         * Protect Event Service from repeated
         * Device Service failures.
         */
        Supplier<DeviceResponse> protectedSupplier =
                CircuitBreaker.decorateSupplier(
                        circuitBreaker,
                        retrySupplier
                );

        try {

            return protectedSupplier.get();

        } catch (Exception exception) {

            log.error(
                    "Device service request failed " +
                            "identifier={} correlationId={}",
                    deviceIdentifier,
                    correlationId,
                    exception
            );

            throw new DeviceServiceUnavailableException(
                    "Device service is unavailable",
                    exception
            );
        }
    }

    /**
     * Determines whether the supplied identifier represents
     * a Device database ID.
     *
     * Examples:
     *
     * "1"      -> true
     * "25"     -> true
     * "DEV-01" -> false
     */
    private boolean isDatabaseId(
            String deviceIdentifier) {

        if (
                deviceIdentifier == null ||
                        deviceIdentifier.isBlank()
        ) {

            return false;
        }

        try {

            Long.parseLong(
                    deviceIdentifier
            );

            return true;

        } catch (NumberFormatException exception) {

            return false;
        }
    }
}