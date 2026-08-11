package com.iotsecurity.event.service;

import com.iotsecurity.event.model.EventType;
import com.iotsecurity.event.model.SecurityEvent;
import com.iotsecurity.event.model.Severity;
import com.iotsecurity.event.repository.SecurityEventRepository;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
public class SecurityEventService {

    private final SecurityEventRepository repository;

    public SecurityEventService(SecurityEventRepository repository) {
        this.repository = repository;
    }

    public List<SecurityEvent> getAllEvents() {
        return repository.findAll();
    }

    public SecurityEvent getEventById(Long id) {
        return repository.findById(id)
                .orElseThrow(() ->
                        new RuntimeException("Event not found: " + id));
    }

    public SecurityEvent createEvent(SecurityEvent event) {
        return repository.save(event);
    }

    public SecurityEvent updateEvent(Long id, SecurityEvent updatedEvent) {

        SecurityEvent existing = getEventById(id);

        existing.setDeviceId(updatedEvent.getDeviceId());
        existing.setEventType(updatedEvent.getEventType());
        existing.setSeverity(updatedEvent.getSeverity());
        existing.setDescription(updatedEvent.getDescription());
        existing.setSourceIp(updatedEvent.getSourceIp());
        existing.setTimestamp(updatedEvent.getTimestamp());
        existing.setStatus(updatedEvent.getStatus());

        return repository.save(existing);
    }

    public void deleteEvent(Long id) {
        SecurityEvent event = getEventById(id);
        repository.delete(event);
    }

    public List<SecurityEvent> getBySeverity(Severity severity) {
        return repository.findBySeverity(severity);
    }

    public List<SecurityEvent> getByEventType(EventType eventType) {
        return repository.findByEventType(eventType);
    }

    public List<SecurityEvent> getByDeviceId(String deviceId) {
        return repository.findByDeviceId(deviceId);
    }
}