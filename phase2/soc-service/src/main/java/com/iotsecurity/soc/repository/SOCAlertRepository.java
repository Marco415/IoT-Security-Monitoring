package com.iotsecurity.soc.repository;

import com.iotsecurity.soc.model.SOCAlert;
import com.iotsecurity.soc.model.Severity;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;
import java.util.UUID;

public interface SOCAlertRepository
        extends JpaRepository<SOCAlert, UUID> {

    long countBySeverity(Severity severity);

    List<SOCAlert> findTop10ByOrderByTimestampDesc();
}