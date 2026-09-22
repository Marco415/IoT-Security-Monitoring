package com.iotsecurity.event.repository;

import com.iotsecurity.event.model.AlertEvent;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;

public interface AlertEventRepository
        extends JpaRepository<AlertEvent, Long> {

    List<AlertEvent> findByAlertId(String alertId);

    List<AlertEvent> findByEventId(String eventId);

    boolean existsByAlertIdAndEventId(
            String alertId,
            String eventId
    );
}