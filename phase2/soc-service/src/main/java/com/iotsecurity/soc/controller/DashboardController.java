package com.iotsecurity.soc.controller;

import com.iotsecurity.soc.dto.dashboard.DashboardAlertResponse;
import com.iotsecurity.soc.dto.dashboard.DashboardResponse;
import com.iotsecurity.soc.dto.dashboard.DashboardServiceResponse;
import com.iotsecurity.soc.model.Severity;
import com.iotsecurity.soc.repository.SOCAlertRepository;
import com.iotsecurity.soc.repository.SOCEventRepository;
import com.iotsecurity.soc.service.ServiceHealthService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.tags.Tag;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.time.LocalDateTime;
import java.util.List;

@RestController
@RequestMapping("/api/soc/dashboard")
@Tag(
        name = "SOC Dashboard",
        description = "SOC dashboard summary and service status."
)
@SecurityRequirement(name = "bearerAuth")
public class DashboardController {

    private final SOCEventRepository eventRepository;

    private final SOCAlertRepository alertRepository;

    private final ServiceHealthService serviceHealthService;

    public DashboardController(
            SOCEventRepository eventRepository,
            SOCAlertRepository alertRepository,
            ServiceHealthService serviceHealthService
    ) {
        this.eventRepository = eventRepository;
        this.alertRepository = alertRepository;
        this.serviceHealthService = serviceHealthService;
    }

    @GetMapping
    @Operation(
            summary = "Get SOC dashboard",
            description =
                    "Returns event totals, alert statistics, " +
                            "recent alerts and service health."
    )
    public DashboardResponse getDashboard() {

        /*
         * Total normalized SOC events.
         */
        long totalEvents =
                eventRepository.count();


        /*
         * SOCAlert currently does not contain a status field.
         *
         * Therefore, we do not query countByStatus().
         *
         * The dashboard treats generated SOC alerts as OPEN
         * until an explicit SOC alert lifecycle is implemented.
         */
        long openAlerts =
                alertRepository.count();


        /*
         * Count alerts by existing Severity enum.
         */
        long highAlerts =
                alertRepository.countBySeverity(
                        Severity.HIGH
                );


        long mediumAlerts =
                alertRepository.countBySeverity(
                        Severity.MEDIUM
                );


        /*
         * Get the ten most recent SOC alerts.
         */
        List<DashboardAlertResponse> recentAlerts =
                alertRepository
                        .findTop10ByOrderByTimestampDesc()
                        .stream()
                        .map(alert ->
                                new DashboardAlertResponse(

                                        alert.getId(),

                                        alert.getRule() != null
                                                ? alert.getRule().name()
                                                : "UNKNOWN",

                                        alert.getSeverity() != null
                                                ? alert.getSeverity().name()
                                                : "UNKNOWN",

                                        alert.getServiceName(),

                                        alert.getUserId(),

                                        /*
                                         * SOCAlert currently has no
                                         * status property.
                                         *
                                         * Generated alerts are displayed
                                         * as OPEN on the dashboard.
                                         */
                                        "OPEN",

                                        alert.getTimestamp()
                                )
                        )
                        .toList();


        /*
         * Check Phase 1 service health.
         */
        List<DashboardServiceResponse> services =
                serviceHealthService
                        .getServiceHealth();


        /*
         * Build dashboard response.
         */
        return new DashboardResponse(
                totalEvents,
                openAlerts,
                highAlerts,
                mediumAlerts,
                services,
                recentAlerts,
                LocalDateTime.now()
        );
    }
}