package com.iotsecurity.event.service;

import com.iotsecurity.event.client.DeviceClient;
import com.iotsecurity.event.dto.DeviceResponse;
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
            LoggerFactory.getLogger(
                    SecurityEventService.class
            );

    private static final String CORRELATION_ID =
            "X-Correlation-ID";

    private final SecurityEventRepository eventRepository;

    private final DeviceClient deviceClient;

    public SecurityEventService(
            SecurityEventRepository eventRepository,
            DeviceClient deviceClient) {

        this.eventRepository =
                eventRepository;

        this.deviceClient =
                deviceClient;
    }

    /**
     * Creates a new security event.
     *
     * If the request contains a status, that status is used.
     *
     * If the request does not contain a status, the event
     * defaults to OPEN.
     */
    public SecurityEvent createEvent(
            EventRequest request) {

        String correlationId =
                MDC.get(CORRELATION_ID);

        log.info(
                "Creating security event deviceIdentifier={} " +
                        "eventType={} severity={} requestedStatus={} correlationId={}",
                request.deviceId(),
                request.eventType(),
                request.severity(),
                request.status(),
                correlationId
        );

        /*
         * Verify that the device exists.
         *
         * DeviceClient supports both:
         *
         * - database ID
         * - actual device_id
         */
        DeviceResponse device =
                deviceClient.getDevice(
                        request.deviceId()
                );

        /*
         * Create the security event.
         */
        SecurityEvent event =
                new SecurityEvent();

        event.setEventId(
                "EVT-" + UUID.randomUUID()
        );

        /*
         * Store the actual device_id from the Device Service.
         */
        event.setDeviceId(
                device.deviceId()
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

        /*
         * FIX:
         *
         * Use the status supplied by the client.
         *
         * If no status was supplied, default to OPEN.
         */
        if (request.status() == null ||
                request.status().isBlank()) {

            event.setStatus("OPEN");

        } else {

            event.setStatus(
                    request.status()
            );
        }

        SecurityEvent savedEvent =
                eventRepository.save(
                        event
                );

        log.info(
                "Security event created eventId={} " +
                        "deviceDatabaseId={} deviceId={} " +
                        "status={} correlationId={}",
                savedEvent.getEventId(),
                device.id(),
                savedEvent.getDeviceId(),
                savedEvent.getStatus(),
                correlationId
        );

        return savedEvent;
    }

    @Transactional
    public List<SecurityEvent> getAllEvents() {

        log.info(
                "Retrieving all security events"
        );

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

        return eventRepository
                .findByDeviceId(deviceId);
    }

    @Transactional
    public List<SecurityEvent> getEventsByStatus(
            String status) {

        log.info(
                "Retrieving security events status={}",
                status
        );

        return eventRepository
                .findByStatus(
                        status.trim().toUpperCase()
                );
    }

    /**
     * Updates an existing security event.
     *
     * The eventId, database ID and original timestamp are preserved.
     *
     * If request.status() is supplied, the event status is updated.
     *
     * If request.status() is null/blank, the existing status is kept.
     */
    public SecurityEvent updateEvent(
            String eventId,
            EventRequest request) {

        String correlationId =
                MDC.get(CORRELATION_ID);

        log.info(
                "Updating security event eventId={} " +
                        "eventType={} severity={} requestedStatus={} correlationId={}",
                eventId,
                request.eventType(),
                request.severity(),
                request.status(),
                correlationId
        );

        /*
         * Find the existing event using the public eventId.
         */
        SecurityEvent event =
                eventRepository
                        .findByEventId(eventId)
                        .orElseThrow(() ->
                                new IllegalArgumentException(
                                        "Security event '" +
                                                eventId +
                                                "' was not found."
                                )
                        );

        /*
         * Verify that the supplied device exists.
         */
        DeviceResponse device =
                deviceClient.getDevice(
                        request.deviceId()
                );

        /*
         * Keep the actual device_id in the event.
         */
        event.setDeviceId(
                device.deviceId()
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

        /*
         * FIX:
         *
         * Previously status was explicitly excluded from
         * normal event updates.
         *
         * It is now updated when the client supplies one.
         *
         * If the client does not supply a status, the existing
         * status is preserved.
         */
        if (request.status() != null &&
                !request.status().isBlank()) {

            String oldStatus = event.getStatus();

            String newStatus =
                    request.status()
                            .trim()
                            .toUpperCase();

            event.setStatus(newStatus);

            log.info(
                    "Security event status changed " +
                            "eventId={} oldStatus={} newStatus={} correlationId={}",
                    eventId,
                    oldStatus,
                    newStatus,
                    correlationId
            );
        }

        /*
         * Do NOT change:
         *
         * - id
         * - eventId
         * - timestamp
         *
         * during a normal event update.
         */

        SecurityEvent updatedEvent =
                eventRepository.save(event);

        log.info(
                "Security event updated successfully " +
                        "eventId={} deviceId={} " +
                        "status={} correlationId={}",
                updatedEvent.getEventId(),
                updatedEvent.getDeviceId(),
                updatedEvent.getStatus(),
                correlationId
        );

        return updatedEvent;
    }

    /**
     * Updates only the status of an existing event.
     *
     * Used by:
     *
     * PATCH /api/events/{eventId}/status?status=RESOLVED
     */
    public SecurityEvent updateStatus(
            String eventId,
            String status) {

        log.info(
                "Updating security event status " +
                        "eventId={} status={}",
                eventId,
                status
        );

        if (status == null || status.isBlank()) {

            throw new IllegalArgumentException(
                    "Status is required."
            );
        }

        SecurityEvent event =
                getEventByEventId(eventId);

        String normalizedStatus =
                status.trim().toUpperCase();

        String oldStatus =
                event.getStatus();

        event.setStatus(
                normalizedStatus
        );

        SecurityEvent updatedEvent =
                eventRepository.save(event);

        log.info(
                "Security event status updated " +
                        "eventId={} oldStatus={} newStatus={}",
                updatedEvent.getEventId(),
                oldStatus,
                updatedEvent.getStatus()
        );

        return updatedEvent;
    }

    public void deleteEvent(
            String eventId) {

        log.warn(
                "Deleting security event eventId={}",
                eventId
        );

        SecurityEvent event =
                getEventByEventId(eventId);

        eventRepository.delete(
                event
        );

        log.info(
                "Security event deleted eventId={}",
                eventId
        );
    }
}