package com.iotsecurity.event.repository;

import com.iotsecurity.event.model.SecurityEvent;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;
import java.util.Optional;

public interface SecurityEventRepository
        extends JpaRepository<SecurityEvent, Long> {

    Optional<SecurityEvent> findByEventId(String eventId);

    List<SecurityEvent> findByDeviceId(String deviceId);

    List<SecurityEvent> findByStatus(String status);
}