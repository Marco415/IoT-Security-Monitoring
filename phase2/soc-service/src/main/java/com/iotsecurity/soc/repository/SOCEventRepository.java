package com.iotsecurity.soc.repository;

import com.iotsecurity.soc.model.SOCEvent;
import org.springframework.data.jpa.repository.JpaRepository;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

public interface SOCEventRepository extends JpaRepository<SOCEvent, UUID> {

    List<SOCEvent> findByEventTypeAndTimestampAfter(
            String eventType,
            LocalDateTime timestamp
    );

    List<SOCEvent> findBySourceIpAndTimestampAfter(
            String sourceIp,
            LocalDateTime timestamp
    );

    List<SOCEvent> findByUserIdAndTimestampAfter(
            String userId,
            LocalDateTime timestamp
    );

    List<SOCEvent> findByServiceNameAndTimestampAfter(
            String serviceName,
            LocalDateTime timestamp
    );

    Optional<SOCEvent> findBySourceSystemAndSourceEventId(
            String sourceSystem,
            Long sourceEventId
    );

    Optional<SOCEvent> findTopBySourceSystemOrderBySourceEventIdDesc(
            String sourceSystem
    );

    boolean existsBySourceSystemAndSourceEventId(
            String sourceSystem,
            Long sourceEventId
    );
}