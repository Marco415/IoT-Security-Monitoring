package com.iotsecurity.gateway;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

@RestController
public class FallbackController {

    private static final Logger log =
            LoggerFactory.getLogger(FallbackController.class);

    @GetMapping("/fallback/event")
    public ResponseEntity<Map<String, Object>> eventFallback() {

        log.error(
                "Event service circuit breaker fallback triggered"
        );

        return ResponseEntity
                .status(HttpStatus.SERVICE_UNAVAILABLE)
                .body(
                        Map.of(
                                "status", 503,
                                "service", "event-service",
                                "message",
                                "Event service is temporarily unavailable",
                                "timestamp",
                                System.currentTimeMillis()
                        )
                );
    }

    @GetMapping("/fallback/device")
    public ResponseEntity<Map<String, Object>> deviceFallback() {

        log.error(
                "Device service circuit breaker fallback triggered"
        );

        return ResponseEntity
                .status(HttpStatus.SERVICE_UNAVAILABLE)
                .body(
                        Map.of(
                                "status", 503,
                                "service", "device-service",
                                "message",
                                "Device service is temporarily unavailable",
                                "timestamp",
                                System.currentTimeMillis()
                        )
                );
    }
}