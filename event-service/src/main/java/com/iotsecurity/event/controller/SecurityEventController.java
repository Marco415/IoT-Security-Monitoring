package com.iotsecurity.event.controller;

import com.iotsecurity.event.dto.EventRequest;
import com.iotsecurity.event.model.SecurityEvent;
import com.iotsecurity.event.service.SecurityEventService;
import jakarta.validation.Valid;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api/events")
public class SecurityEventController {

    private final SecurityEventService eventService;

    public SecurityEventController(SecurityEventService eventService) {
        this.eventService = eventService;
    }

    @PostMapping
    public ResponseEntity<SecurityEvent> createEvent(
            @Valid @RequestBody EventRequest request) {

        SecurityEvent event = eventService.createEvent(request);

        return ResponseEntity
                .status(HttpStatus.CREATED)
                .body(event);
    }

    @GetMapping
    public ResponseEntity<List<SecurityEvent>> getAllEvents() {

        return ResponseEntity.ok(
                eventService.getAllEvents()
        );
    }

    @GetMapping("/{eventId}")
    public ResponseEntity<SecurityEvent> getEvent(
            @PathVariable String eventId) {

        return ResponseEntity.ok(
                eventService.getEventByEventId(eventId)
        );
    }

    @GetMapping("/device/{deviceId}")
    public ResponseEntity<List<SecurityEvent>> getEventsByDevice(
            @PathVariable String deviceId) {

        return ResponseEntity.ok(
                eventService.getEventsByDeviceId(deviceId)
        );
    }

    @GetMapping("/status/{status}")
    public ResponseEntity<List<SecurityEvent>> getEventsByStatus(
            @PathVariable String status) {

        return ResponseEntity.ok(
                eventService.getEventsByStatus(status.toUpperCase())
        );
    }

    @PatchMapping("/{eventId}/status")
    public ResponseEntity<SecurityEvent> updateStatus(
            @PathVariable String eventId,
            @RequestParam String status) {

        return ResponseEntity.ok(
                eventService.updateStatus(eventId, status)
        );
    }

    @DeleteMapping("/{eventId}")
    public ResponseEntity<Void> deleteEvent(
            @PathVariable String eventId) {

        eventService.deleteEvent(eventId);

        return ResponseEntity.noContent().build();
    }
}