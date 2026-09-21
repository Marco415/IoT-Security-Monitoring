package com.iotsecurity.soc.service;

import com.iotsecurity.soc.dto.EventRequest;
import com.iotsecurity.soc.model.SOCEvent;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.util.UUID;

@Service
public class EventNormalizationService {

    private static final Logger log =
            LoggerFactory.getLogger(EventNormalizationService.class);

    public SOCEvent normalize(EventRequest request) {

        log.info(
                "Normalizing incoming SOC event serviceName={} " +
                        "eventType={} severity={} userId={} sourceIp={} " +
                        "endpoint={} httpMethod={} statusCode={} correlationId={}",
                request.serviceName(),
                request.eventType(),
                request.severity(),
                request.userId(),
                request.sourceIp(),
                request.endpoint(),
                request.httpMethod(),
                request.statusCode(),
                request.correlationId()
        );

        LocalDateTime timestamp =
                request.timestamp() != null
                        ? request.timestamp()
                        : LocalDateTime.now();

        if (request.timestamp() == null) {
            log.debug(
                    "SOC event timestamp not supplied; using current timestamp"
            );
        }

        SOCEvent event = new SOCEvent(
                UUID.randomUUID(),
                timestamp,
                request.serviceName(),
                request.eventType(),
                request.severity(),
                request.userId(),
                request.sourceIp(),
                request.endpoint(),
                request.httpMethod(),
                request.statusCode(),
                request.message(),
                request.correlationId(),
                request.affectedEntity()
        );

        log.info(
                "SOC event normalized eventId={} timestamp={} " +
                        "serviceName={} eventType={} severity={} " +
                        "correlationId={}",
                event.getEventId(),
                event.getTimestamp(),
                event.getServiceName(),
                event.getEventType(),
                event.getSeverity(),
                event.getCorrelationId()
        );

        return event;
    }
}