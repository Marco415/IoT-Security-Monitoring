package com.iotsecurity.event.repository;

import com.iotsecurity.event.model.Alert;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;
import java.util.Optional;

public interface AlertRepository extends JpaRepository<Alert, Long> {

    Optional<Alert> findByAlertId(String alertId);

    List<Alert> findByStatus(String status);

    List<Alert> findByRuleName(String ruleName);
}