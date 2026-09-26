package com.iotsecurity.auth.controller;

import com.iotsecurity.auth.dto.AuthEventResponse;
import com.iotsecurity.auth.entity.AuthEvent;
import com.iotsecurity.auth.repository.AuthEventRepository;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/internal/auth-events")
public class InternalAuthEventController {

    private static final Logger log =
            LoggerFactory.getLogger(InternalAuthEventController.class);

    private static final String INTERNAL_SERVICE_KEY_HEADER =
            "X-Internal-Service-Key";

    private final AuthEventRepository authEventRepository;
    private final String internalServiceKey;

    public InternalAuthEventController(
            AuthEventRepository authEventRepository,
            @Value("${security.internal-service-key}")
            String internalServiceKey
    ) {
        this.authEventRepository = authEventRepository;
        this.internalServiceKey = internalServiceKey;
    }

    @GetMapping
    public ResponseEntity<?> getAuthEvents(
            @RequestHeader(
                    value = INTERNAL_SERVICE_KEY_HEADER,
                    required = false
            )
            String providedServiceKey
    ) {

        if (providedServiceKey == null
                || providedServiceKey.isBlank()
                || !internalServiceKey.equals(providedServiceKey)) {

            log.warn(
                    "Rejected unauthorized internal Auth event request"
            );

            return ResponseEntity
                    .status(HttpStatus.UNAUTHORIZED)
                    .body("Unauthorized");
        }

        List<AuthEventResponse> events =
                authEventRepository.findAll()
                        .stream()
                        .map(AuthEventResponse::fromEntity)
                        .toList();

        log.info(
                "Internal Auth event request returned {} events",
                events.size()
        );

        return ResponseEntity.ok(events);
    }
}