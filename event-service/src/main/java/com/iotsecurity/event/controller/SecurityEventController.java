package com.iotsecurity.event.controller;

import com.iotsecurity.event.dto.EventRequest;
import com.iotsecurity.event.model.SecurityEvent;
import com.iotsecurity.event.service.SecurityEventService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@Tag(
        name = "Security Events",
        description = "IoT security event management operations"
)
@RestController
@RequestMapping("/api/events")
public class SecurityEventController {

    private static final Logger log =
            LoggerFactory.getLogger(
                    SecurityEventController.class
            );

    private final SecurityEventService eventService;

    public SecurityEventController(
            SecurityEventService eventService) {

        this.eventService = eventService;
    }

    @Operation(
            summary = "Create security event",
            description =
                    "Creates a new security event. " +
                            "If status is omitted, the event defaults to OPEN."
    )
    @ApiResponses({
            @ApiResponse(
                    responseCode = "201",
                    description = "Security event created successfully"
            ),
            @ApiResponse(
                    responseCode = "400",
                    description = "Invalid event data"
            )
    })
    @SecurityRequirement(name = "bearerAuth")
    @PostMapping
    public ResponseEntity<SecurityEvent> createEvent(
            @Valid @RequestBody EventRequest request) {

        log.info(
                "Received security event request " +
                        "deviceId={} eventType={} severity={} status={}",
                request.deviceId(),
                request.eventType(),
                request.severity(),
                request.status()
        );

        SecurityEvent event =
                eventService.createEvent(request);

        log.info(
                "Security event request completed " +
                        "eventId={} status={}",
                event.getEventId(),
                event.getStatus()
        );

        return ResponseEntity
                .status(HttpStatus.CREATED)
                .body(event);
    }

    @Operation(
            summary = "Get all security events",
            description =
                    "Returns all security events recorded by the monitoring system."
    )
    @ApiResponses({
            @ApiResponse(
                    responseCode = "200",
                    description = "Events retrieved successfully"
            )
    })
    @SecurityRequirement(name = "bearerAuth")
    @GetMapping
    public ResponseEntity<List<SecurityEvent>> getAllEvents() {

        log.info(
                "Received request to retrieve all security events"
        );

        return ResponseEntity.ok(
                eventService.getAllEvents()
        );
    }

    @Operation(
            summary = "Get security event by event ID",
            description =
                    "Returns a security event using its eventId."
    )
    @ApiResponses({
            @ApiResponse(
                    responseCode = "200",
                    description = "Event found"
            ),
            @ApiResponse(
                    responseCode = "404",
                    description = "Event not found"
            )
    })
    @SecurityRequirement(name = "bearerAuth")
    @GetMapping("/{eventId}")
    public ResponseEntity<SecurityEvent> getEvent(
            @Parameter(
                    description = "Unique security event identifier",
                    example = "EVT-14c75691-cc88-45af-9405-03227bdbe0f6",
                    required = true
            )
            @PathVariable String eventId) {

        log.info(
                "Received request to retrieve security event eventId={}",
                eventId
        );

        return ResponseEntity.ok(
                eventService.getEventByEventId(eventId)
        );
    }

    @Operation(
            summary = "Update security event",
            description =
                    "Updates an existing security event using its eventId. " +
                            "If status is supplied, the existing status is updated. " +
                            "If status is omitted, the existing status is preserved."
    )
    @ApiResponses({
            @ApiResponse(
                    responseCode = "200",
                    description = "Security event updated successfully"
            ),
            @ApiResponse(
                    responseCode = "400",
                    description = "Invalid event data"
            ),
            @ApiResponse(
                    responseCode = "404",
                    description = "Security event not found"
            )
    })
    @SecurityRequirement(name = "bearerAuth")
    @PutMapping("/{eventId}")
    public ResponseEntity<SecurityEvent> updateEvent(
            @Parameter(
                    description = "Unique security event identifier",
                    example = "EVT-14c75691-cc88-45af-9405-03227bdbe0f6",
                    required = true
            )
            @PathVariable String eventId,

            @Valid @RequestBody EventRequest request) {

        log.info(
                "Received request to update security event " +
                        "eventId={} status={}",
                eventId,
                request.status()
        );

        SecurityEvent updatedEvent =
                eventService.updateEvent(
                        eventId,
                        request
                );

        log.info(
                "Security event updated eventId={} status={}",
                updatedEvent.getEventId(),
                updatedEvent.getStatus()
        );

        return ResponseEntity.ok(updatedEvent);
    }

    @Operation(
            summary = "Get security events by device",
            description =
                    "Returns all security events associated with a specific IoT device."
    )
    @ApiResponses({
            @ApiResponse(
                    responseCode = "200",
                    description = "Security events retrieved successfully"
            )
    })
    @SecurityRequirement(name = "bearerAuth")
    @GetMapping("/device/{deviceId}")
    public ResponseEntity<List<SecurityEvent>>
    getEventsByDevice(
            @Parameter(
                    description = "Unique IoT device identifier",
                    example = "DEV-001",
                    required = true
            )
            @PathVariable String deviceId) {

        log.info(
                "Received request to retrieve security events deviceId={}",
                deviceId
        );

        return ResponseEntity.ok(
                eventService.getEventsByDeviceId(deviceId)
        );
    }

    @Operation(
            summary = "Get security events by status",
            description =
                    "Returns all security events matching the specified status."
    )
    @ApiResponses({
            @ApiResponse(
                    responseCode = "200",
                    description = "Security events retrieved successfully"
            )
    })
    @SecurityRequirement(name = "bearerAuth")
    @GetMapping("/status/{status}")
    public ResponseEntity<List<SecurityEvent>>
    getEventsByStatus(
            @Parameter(
                    description = "Security event status",
                    example = "OPEN",
                    required = true
            )
            @PathVariable String status) {

        log.info(
                "Received request to retrieve security events status={}",
                status
        );

        return ResponseEntity.ok(
                eventService.getEventsByStatus(status)
        );
    }

    @Operation(
            summary = "Update security event status",
            description =
                    "Updates only the status of an existing security event."
    )
    @ApiResponses({
            @ApiResponse(
                    responseCode = "200",
                    description =
                            "Security event status updated successfully"
            ),
            @ApiResponse(
                    responseCode = "400",
                    description = "Invalid status"
            ),
            @ApiResponse(
                    responseCode = "404",
                    description = "Security event not found"
            )
    })
    @SecurityRequirement(name = "bearerAuth")
    @PatchMapping("/{eventId}/status")
    public ResponseEntity<SecurityEvent> updateStatus(
            @Parameter(
                    description = "Unique security event identifier",
                    example = "EVT-14c75691-cc88-45af-9405-03227bdbe0f6",
                    required = true
            )
            @PathVariable String eventId,

            @Parameter(
                    description = "New status for the security event",
                    example = "RESOLVED",
                    required = true
            )
            @RequestParam String status) {

        log.info(
                "Received request to update event status " +
                        "eventId={} status={}",
                eventId,
                status
        );

        return ResponseEntity.ok(
                eventService.updateStatus(
                        eventId,
                        status
                )
        );
    }

    @Operation(
            summary = "Delete security event",
            description =
                    "Deletes a security event using its eventId."
    )
    @ApiResponses({
            @ApiResponse(
                    responseCode = "204",
                    description =
                            "Security event deleted successfully"
            ),
            @ApiResponse(
                    responseCode = "404",
                    description =
                            "Security event not found"
            )
    })
    @SecurityRequirement(name = "bearerAuth")
    @DeleteMapping("/{eventId}")
    public ResponseEntity<Void> deleteEvent(
            @PathVariable String eventId) {

        log.warn(
                "Received request to delete security event eventId={}",
                eventId
        );

        eventService.deleteEvent(eventId);

        return ResponseEntity
                .noContent()
                .build();
    }
}