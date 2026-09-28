package com.iotsecurity.soc.repository;

import com.iotsecurity.soc.model.DetectionRule;
import com.iotsecurity.soc.model.SOCAlert;
import com.iotsecurity.soc.model.Severity;
import org.springframework.data.jpa.repository.JpaRepository;

import java.time.LocalDateTime;
import java.util.List;
import java.util.UUID;

public interface SOCAlertRepository
        extends JpaRepository<SOCAlert, UUID> {

    List<SOCAlert> findByRuleAndSourceIpAndTimestampAfter(
            DetectionRule rule,
            String sourceIp,
            LocalDateTime timestamp
    );

    List<SOCAlert> findByRuleAndUserIdAndTimestampAfter(
            DetectionRule rule,
            String userId,
            LocalDateTime timestamp
    );

    long countBySeverity(Severity severity);

    List<SOCAlert> findTop10ByOrderByTimestampDesc();
}