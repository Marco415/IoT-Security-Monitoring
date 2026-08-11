package com.iotsecurity.event.repository;

import com.iotsecurity.event.model.EventType;
import com.iotsecurity.event.model.SecurityEvent;
import com.iotsecurity.event.model.Severity;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;

public interface SecurityEventRepository
        extends JpaRepository<SecurityEvent, Long> {

    List<SecurityEvent> findBySeverity(Severity severity);

    List<SecurityEvent> findByEventType(EventType eventType);

    List<SecurityEvent> findByDeviceId(String deviceId);
}