package com.iotsecurity.event.service;

import com.iotsecurity.event.client.DeviceClient;
import com.iotsecurity.event.dto.EventRequest;
import com.iotsecurity.event.model.SecurityEvent;
import com.iotsecurity.event.repository.SecurityEventRepository;
import jakarta.transaction.Transactional;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.util.List;

@Service
@Transactional
public class SecurityEventService {

    private final SecurityEventRepository eventRepository;
    private final DeviceClient deviceClient;

    public SecurityEventService(
            SecurityEventRepository eventRepository,
            DeviceClient deviceClient) {

        this.eventRepository = eventRepository;
        this.deviceClient = deviceClient;
    }

    public SecurityEvent createEvent(EventRequest request) {

        // Verify that the device exists before creating the event.
        deviceClient.getDevice(request.deviceId());

        SecurityEvent event = new SecurityEvent();

        event.setEventId("EVT-" + java.util.UUID.randomUUID());
        event.setDeviceId(request.deviceId());
        event.setEventType(request.eventType());
        event.setSeverity(request.severity());
        event.setDescription(request.description());
        event.setSourceIp(request.sourceIp());
        event.setTimestamp(LocalDateTime.now());
        event.setStatus("OPEN");

        return eventRepository.save(event);
    }

    @Transactional
    public List<SecurityEvent> getAllEvents() {
        return eventRepository.findAll();
    }

    @Transactional
    public SecurityEvent getEventByEventId(String eventId) {

        return eventRepository
                .findByEventId(eventId)
                .orElseThrow(() ->
                        new IllegalArgumentException(
                                "Security event '" + eventId + "' was not found."
                        )
                );
    }

    @Transactional
    public List<SecurityEvent> getEventsByDeviceId(String deviceId) {

        return eventRepository.findByDeviceId(deviceId);
    }

    @Transactional
    public List<SecurityEvent> getEventsByStatus(String status) {

        return eventRepository.findByStatus(status);
    }

    public SecurityEvent updateStatus(
            String eventId,
            String status) {

        SecurityEvent event = getEventByEventId(eventId);

        event.setStatus(status.toUpperCase());

        return eventRepository.save(event);
    }

    public void deleteEvent(String eventId) {

        SecurityEvent event = getEventByEventId(eventId);

        eventRepository.delete(event);
    }
}