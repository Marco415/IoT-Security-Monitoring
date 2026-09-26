package com.iotsecurity.event.repository;

import com.iotsecurity.event.model.SecurityEvent;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.domain.Pageable;

import java.util.List;
import java.util.Optional;

public interface SecurityEventRepository
        extends JpaRepository<SecurityEvent, Long> {

    Optional<SecurityEvent> findByEventId(String eventId);

    List<SecurityEvent> findByDeviceId(String deviceId);

    List<SecurityEvent> findByStatus(String status);

    List<SecurityEvent> findByIdGreaterThanOrderByIdAsc(
            Long id,
            Pageable pageable
    );
}