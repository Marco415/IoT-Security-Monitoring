package com.iotsecurity.event.controller;

import com.iotsecurity.event.model.EventType;
import com.iotsecurity.event.model.SecurityEvent;
import com.iotsecurity.event.model.Severity;
import com.iotsecurity.event.service.SecurityEventService;
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

    @GetMapping
    public ResponseEntity<List<SecurityEvent>> getEvents(
            @RequestParam(required = false) Severity severity,
            @RequestParam(required = false) EventType eventType,
            @RequestParam(required = false) String deviceId) {

        if (severity != null) {
            return ResponseEntity.ok(
                    eventService.getBySeverity(severity)
            );
        }

        if (eventType != null) {
            return ResponseEntity.ok(
                    eventService.getByEventType(eventType)
            );
        }

        if (deviceId != null) {
            return ResponseEntity.ok(
                    eventService.getByDeviceId(deviceId)
            );
        }

        return ResponseEntity.ok(
                eventService.getAllEvents()
        );
    }

    @GetMapping("/{id}")
    public ResponseEntity<SecurityEvent> getEvent(
            @PathVariable Long id) {

        return ResponseEntity.ok(
                eventService.getEventById(id)
        );
    }

    @PostMapping
    public ResponseEntity<SecurityEvent> createEvent(
            @RequestBody SecurityEvent event) {

        SecurityEvent created =
                eventService.createEvent(event);

        return ResponseEntity
                .status(HttpStatus.CREATED)
                .body(created);
    }

    @PutMapping("/{id}")
    public ResponseEntity<SecurityEvent> updateEvent(
            @PathVariable Long id,
            @RequestBody SecurityEvent event) {

        return ResponseEntity.ok(
                eventService.updateEvent(id, event)
        );
    }

    @DeleteMapping("/{id}")
    public ResponseEntity<Void> deleteEvent(
            @PathVariable Long id) {

        eventService.deleteEvent(id);

        return ResponseEntity.noContent().build();
    }
}