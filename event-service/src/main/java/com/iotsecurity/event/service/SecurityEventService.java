package com.iotsecurity.event.service;

import com.iotsecurity.event.client.DeviceClient;
import com.iotsecurity.event.dto.EventRequest;
import com.iotsecurity.event.model.SecurityEvent;
import com.iotsecurity.event.repository.SecurityEventRepository;
import jakarta.transaction.Transactional;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.slf4j.MDC;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.util.List;
import java.util.UUID;

@Service
@Transactional
public class SecurityEventService {

    private static final Logger log =
            LoggerFactory.getLogger(SecurityEventService.class);

    private static final String CORRELATION_ID =
            "X-Correlation-ID";

    private final SecurityEventRepository eventRepository;

    private final DeviceClient deviceClient;

    public SecurityEventService(
            SecurityEventRepository eventRepository,
            DeviceClient deviceClient) {

        this.eventRepository = eventRepository;
        this.deviceClient = deviceClient;
    }

    public SecurityEvent createEvent(EventRequest request) {

        String correlationId =
                MDC.get(CORRELATION_ID);

        log.info(
                "Creating security event deviceId={} eventType={} severity={} correlationId={}",
                request.deviceId(),
                request.eventType(),
                request.severity(),
                correlationId
        );

        /*
         * Verify that the device exists before creating
         * the security event.
         *
         * DeviceClient handles:
         * - Retry
         * - Circuit breaker
         * - Correlation ID forwarding
         */
        deviceClient.getDevice(request.deviceId());

        SecurityEvent event = new SecurityEvent();

        event.setEventId(
                "EVT-" + UUID.randomUUID()
        );

        event.setDeviceId(
                request.deviceId()
        );

        event.setEventType(
                request.eventType()
        );

        event.setSeverity(
                request.severity()
        );

        event.setDescription(
                request.description()
        );

        event.setSourceIp(
                request.sourceIp()
        );

        event.setTimestamp(
                LocalDateTime.now()
        );

        event.setStatus("OPEN");

        SecurityEvent savedEvent =
                eventRepository.save(event);

        log.info(
                "Security event created eventId={} deviceId={} status={} correlationId={}",
                savedEvent.getEventId(),
                savedEvent.getDeviceId(),
                savedEvent.getStatus(),
                correlationId
        );

        return savedEvent;
    }

    @Transactional
    public List<SecurityEvent> getAllEvents() {

        log.info("Retrieving all security events");

        return eventRepository.findAll();
    }

    @Transactional
    public SecurityEvent getEventByEventId(
            String eventId) {

        log.info(
                "Retrieving security event eventId={}",
                eventId
        );

        return eventRepository
                .findByEventId(eventId)
                .orElseThrow(() ->
                        new IllegalArgumentException(
                                "Security event '" +
                                        eventId +
                                        "' was not found."
                        )
                );
    }

    @Transactional
    public List<SecurityEvent> getEventsByDeviceId(
            String deviceId) {

        log.info(
                "Retrieving security events deviceId={}",
                deviceId
        );

        return eventRepository.findByDeviceId(deviceId);
    }

    @Transactional
    public List<SecurityEvent> getEventsByStatus(
            String status) {

        log.info(
                "Retrieving security events status={}",
                status
        );

        return eventRepository.findByStatus(status);
    }

    public SecurityEvent updateStatus(
            String eventId,
            String status) {

        log.info(
                "Updating security event status eventId={} status={}",
                eventId,
                status
        );

        SecurityEvent event =
                getEventByEventId(eventId);

        event.setStatus(
                status.toUpperCase()
        );

        SecurityEvent updatedEvent =
                eventRepository.save(event);

        log.info(
                "Security event status updated eventId={} status={}",
                updatedEvent.getEventId(),
                updatedEvent.getStatus()
        );

        return updatedEvent;
    }

    public void deleteEvent(String eventId) {

        log.warn(
                "Deleting security event eventId={}",
                eventId
        );

        SecurityEvent event =
                getEventByEventId(eventId);

        eventRepository.delete(event);

        log.info(
                "Security event deleted eventId={}",
                eventId
        );
    }
}