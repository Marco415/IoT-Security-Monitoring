package com.iotsecurity.event.controller;

import com.iotsecurity.event.model.SecurityEvent;
import com.iotsecurity.event.repository.SecurityEventRepository;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.tags.Tag;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.domain.PageRequest;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ResponseStatusException;

import java.util.List;

@RestController
@RequestMapping("/api/internal/security-events")
@Tag(
        name = "Internal Security Events",
        description = "Internal SOC ingestion endpoint"
)
public class InternalSecurityEventController {

    private final SecurityEventRepository securityEventRepository;

    private final String internalApiKey;


    public InternalSecurityEventController(
            SecurityEventRepository securityEventRepository,
            @Value("${soc.internal-api-key}")
            String internalApiKey
    ) {

        this.securityEventRepository =
                securityEventRepository;

        this.internalApiKey =
                internalApiKey;
    }


    @GetMapping
    @Operation(
            summary = "Get security events for SOC ingestion",
            description =
                    "Returns event-service security events after " +
                            "the supplied database ID."
    )
    public List<SecurityEvent> getSecurityEvents(

            @Parameter(
                    description =
                            "Only events with database ID greater than this value"
            )
            @RequestParam(
                    defaultValue = "0"
            )
            Long afterId,

            @Parameter(
                    description =
                            "Maximum number of events to return"
            )
            @RequestParam(
                    defaultValue = "100"
            )
            Integer limit,

            @RequestHeader(
                    value = "X-Internal-API-Key",
                    required = false
            )
            String providedApiKey
    ) {

        validateApiKey(
                providedApiKey
        );

        int safeLimit =
                Math.min(
                        Math.max(limit, 1),
                        500
                );

        return securityEventRepository
                .findByIdGreaterThanOrderByIdAsc(
                        afterId,
                        PageRequest.of(
                                0,
                                safeLimit
                        )
                );
    }


    private void validateApiKey(
            String providedApiKey
    ) {

        if (providedApiKey == null ||
                !providedApiKey.equals(internalApiKey)) {

            throw new ResponseStatusException(
                    HttpStatus.UNAUTHORIZED,
                    "Invalid internal API key"
            );
        }
    }
}