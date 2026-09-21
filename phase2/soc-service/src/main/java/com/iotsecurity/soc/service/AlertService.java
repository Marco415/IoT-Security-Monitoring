package com.iotsecurity.soc.service;

import com.iotsecurity.soc.model.DetectionRule;
import com.iotsecurity.soc.model.SOCAlert;
import com.iotsecurity.soc.model.SOCEvent;
import com.iotsecurity.soc.model.Severity;
import com.iotsecurity.soc.repository.SOCAlertRepository;
import com.iotsecurity.soc.repository.SOCEventRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.util.List;

@Service
public class AlertService {

    private static final Logger log =
            LoggerFactory.getLogger(AlertService.class);

    private final SOCEventRepository eventRepository;
    private final SOCAlertRepository alertRepository;

    public AlertService(
            SOCEventRepository eventRepository,
            SOCAlertRepository alertRepository
    ) {
        this.eventRepository = eventRepository;
        this.alertRepository = alertRepository;
    }

    public SOCEvent saveEvent(SOCEvent event) {

        log.info(
                "Saving normalized SOC event eventId={} serviceName={} " +
                        "eventType={} severity={} userId={} sourceIp={} " +
                        "endpoint={} statusCode={} correlationId={}",
                event.getEventId(),
                event.getServiceName(),
                event.getEventType(),
                event.getSeverity(),
                event.getUserId(),
                event.getSourceIp(),
                event.getEndpoint(),
                event.getStatusCode(),
                event.getCorrelationId()
        );

        SOCEvent savedEvent = eventRepository.save(event);

        log.info(
                "SOC event saved successfully eventId={} serviceName={} " +
                        "eventType={} severity={} correlationId={}",
                savedEvent.getEventId(),
                savedEvent.getServiceName(),
                savedEvent.getEventType(),
                savedEvent.getSeverity(),
                savedEvent.getCorrelationId()
        );

        return savedEvent;
    }

    public List<SOCEvent> findEventsByUser(
            String userId,
            LocalDateTime timestamp
    ) {

        log.debug(
                "Searching SOC events by userId={} timestampAfter={}",
                userId,
                timestamp
        );

        List<SOCEvent> events =
                eventRepository
                        .findByUserIdAndTimestampAfter(userId, timestamp);

        log.debug(
                "SOC event search completed userId={} timestampAfter={} resultCount={}",
                userId,
                timestamp,
                events.size()
        );

        return events;
    }

    public List<SOCEvent> findEventsByIp(
            String sourceIp,
            LocalDateTime timestamp
    ) {

        log.debug(
                "Searching SOC events by sourceIp={} timestampAfter={}",
                sourceIp,
                timestamp
        );

        List<SOCEvent> events =
                eventRepository
                        .findBySourceIpAndTimestampAfter(
                                sourceIp,
                                timestamp
                        );

        log.debug(
                "SOC event search completed sourceIp={} timestampAfter={} resultCount={}",
                sourceIp,
                timestamp,
                events.size()
        );

        return events;
    }

    public List<SOCEvent> findEventsByService(
            String serviceName,
            LocalDateTime timestamp
    ) {

        log.debug(
                "Searching SOC events by serviceName={} timestampAfter={}",
                serviceName,
                timestamp
        );

        List<SOCEvent> events =
                eventRepository
                        .findByServiceNameAndTimestampAfter(
                                serviceName,
                                timestamp
                        );

        log.debug(
                "SOC event search completed serviceName={} timestampAfter={} resultCount={}",
                serviceName,
                timestamp,
                events.size()
        );

        return events;
    }

    public SOCAlert createAlert(
            DetectionRule rule,
            Severity severity,
            SOCEvent event,
            int eventCount,
            String message
    ) {

        log.warn(
                "Creating SOC alert rule={} severity={} eventId={} " +
                        "serviceName={} eventType={} eventCount={} " +
                        "userId={} sourceIp={} correlationId={} message={}",
                rule,
                severity,
                event.getEventId(),
                event.getServiceName(),
                event.getEventType(),
                eventCount,
                event.getUserId(),
                event.getSourceIp(),
                event.getCorrelationId(),
                message
        );

        SOCAlert alert = new SOCAlert();

        alert.setRule(rule);
        alert.setSeverity(severity);
        alert.setTimestamp(LocalDateTime.now());
        alert.setUserId(event.getUserId());
        alert.setSourceIp(event.getSourceIp());
        alert.setServiceName(event.getServiceName());
        alert.setEventCount(eventCount);
        alert.setMessage(message);

        SOCAlert savedAlert =
                alertRepository.save(alert);

        log.warn(
                "SOC alert created successfully alertId={} rule={} " +
                        "severity={} eventCount={} serviceName={} " +
                        "userId={} sourceIp={}",
                savedAlert.getId(),
                savedAlert.getRule(),
                savedAlert.getSeverity(),
                savedAlert.getEventCount(),
                savedAlert.getServiceName(),
                savedAlert.getUserId(),
                savedAlert.getSourceIp()
        );

        return savedAlert;
    }
}