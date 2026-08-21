package com.iotsecurity.event.controller;

import com.iotsecurity.event.dto.EventRequest;
import com.iotsecurity.event.model.SecurityEvent;
import com.iotsecurity.event.service.SecurityEventService;
import jakarta.validation.Valid;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;

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

    @PostMapping
    public ResponseEntity<SecurityEvent> createEvent(
            @Valid @RequestBody EventRequest request) {

        log.info(
                "Received security event request deviceId={} eventType={} severity={}",
                request.deviceId(),
                request.eventType(),
                request.severity()
        );

        SecurityEvent event =
                eventService.createEvent(request);

        log.info(
                "Security event request completed eventId={}",
                event.getEventId()
        );

        return ResponseEntity
                .status(HttpStatus.CREATED)
                .body(event);
    }

    @GetMapping
    public ResponseEntity<List<SecurityEvent>> getAllEvents() {

        log.info(
                "Received request to retrieve all security events"
        );

        return ResponseEntity.ok(
                eventService.getAllEvents()
        );
    }

    @GetMapping("/{eventId}")
    public ResponseEntity<SecurityEvent> getEvent(
            @PathVariable String eventId) {

        log.info(
                "Received request to retrieve security event eventId={}",
                eventId
        );

        return ResponseEntity.ok(
                eventService.getEventByEventId(eventId)
        );
    }

    @PutMapping("/{eventId}")
    public ResponseEntity<SecurityEvent> updateEvent(
            @PathVariable String eventId,
            @Valid @RequestBody EventRequest request) {

        log.info(
                "Received request to update security event eventId={}",
                eventId
        );

        SecurityEvent updatedEvent =
                eventService.updateEvent(
                        eventId,
                        request
                );

        log.info(
                "Security event updated eventId={}",
                updatedEvent.getEventId()
        );

        return ResponseEntity.ok(updatedEvent);
    }

    @GetMapping("/device/{deviceId}")
    public ResponseEntity<List<SecurityEvent>>
    getEventsByDevice(
            @PathVariable String deviceId) {

        log.info(
                "Received request to retrieve security events deviceId={}",
                deviceId
        );

        return ResponseEntity.ok(
                eventService.getEventsByDeviceId(deviceId)
        );
    }

    @GetMapping("/status/{status}")
    public ResponseEntity<List<SecurityEvent>>
    getEventsByStatus(
            @PathVariable String status) {

        log.info(
                "Received request to retrieve security events status={}",
                status
        );

        return ResponseEntity.ok(
                eventService.getEventsByStatus(status)
        );
    }

    @PatchMapping("/{eventId}/status")
    public ResponseEntity<SecurityEvent> updateStatus(
            @PathVariable String eventId,
            @RequestParam String status) {

        log.info(
                "Received request to update event status eventId={} status={}",
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

    @DeleteMapping("/{eventId}")
    public ResponseEntity<Void> deleteEvent(
            @PathVariable String eventId) {

        log.warn(
                "Received request to delete security event eventId={}",
                eventId
        );

        eventService.deleteEvent(eventId);

        return ResponseEntity.noContent().build();
    }
}