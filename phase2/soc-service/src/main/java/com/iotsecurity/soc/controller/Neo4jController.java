package com.iotsecurity.soc.controller;

import com.iotsecurity.soc.service.Neo4jGraphService;
import com.iotsecurity.soc.service.Neo4jQueryService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.tags.Tag;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/api/soc/graph")
@Tag(
        name = "SOC Knowledge Graph",
        description =
                "Neo4j security knowledge graph operations"
)
@SecurityRequirement(name = "bearerAuth")
public class Neo4jController {

    private final Neo4jGraphService graphService;
    private final Neo4jQueryService queryService;


    public Neo4jController(
            Neo4jGraphService graphService,
            Neo4jQueryService queryService
    ) {

        this.graphService = graphService;
        this.queryService = queryService;
    }


    // ============================================================
    // CREATE COMPLETE FAILED-LOGIN GRAPH
    // ============================================================

    @PostMapping("/failed-login")
    @Operation(
            summary = "Create failed-login graph",
            description =
                    "Creates the User, Event, Alert, Threat, Service " +
                            "and Control relationships for a multiple failed-login detection."
    )
    @ApiResponses({
            @ApiResponse(
                    responseCode = "200",
                    description =
                            "Failed-login graph created successfully"
            ),
            @ApiResponse(
                    responseCode = "400",
                    description =
                            "Invalid failed-login graph parameters"
            ),
            @ApiResponse(
                    responseCode = "401",
                    description =
                            "Authentication required"
            )
    })
    public ResponseEntity<String> createFailedLoginGraph(

            @RequestParam String username,

            @RequestParam List<String> eventIds,

            @RequestParam String alertId,

            @RequestParam(
                    defaultValue = "HIGH"
            )
            String severity,

            @RequestParam(
                    defaultValue = "auth-service"
            )
            String affectedService
    ) {

        graphService.createFailedLoginGraph(
                username,
                eventIds,
                alertId,
                severity,
                affectedService
        );

        return ResponseEntity.ok(
                "Failed-login graph created successfully"
        );
    }


    // ============================================================
    // QUERY 1
    // ============================================================

    @GetMapping("/alerts/service/{serviceName}")
    @Operation(
            summary = "Find alerts affecting a service",
            description =
                    "Returns all Alert nodes whose affectedService " +
                            "matches the supplied service."
    )
    public ResponseEntity<List<Map<String, Object>>>
    alertsAffectingService(
            @PathVariable String serviceName
    ) {

        return ResponseEntity.ok(
                queryService.alertsAffectingService(
                        serviceName
                )
        );
    }


    // ============================================================
    // QUERY 2
    // ============================================================

    @GetMapping("/alerts/high-severity/users")
    @Operation(
            summary = "Find users linked to high-severity alerts",
            description =
                    "Returns users connected through TRIGGERED and " +
                            "CREATED_ALERT relationships to HIGH severity alerts."
    )
    public ResponseEntity<List<Map<String, Object>>>
    highSeverityUsers() {

        return ResponseEntity.ok(
                queryService.usersLinkedToHighSeverityAlerts()
        );
    }


    // ============================================================
    // QUERY 3
    // ============================================================

    @GetMapping("/threats/service/{serviceName}")
    @Operation(
            summary = "Find threats targeting a service"
    )
    public ResponseEntity<List<Map<String, Object>>>
    threatsForService(
            @PathVariable String serviceName
    ) {

        return ResponseEntity.ok(
                queryService.threatsLinkedToService(
                        serviceName
                )
        );
    }


    // ============================================================
    // QUERY 4
    // ============================================================

    @GetMapping("/controls/alert/{alertId}")
    @Operation(
            summary = "Find controls mitigating an alert"
    )
    public ResponseEntity<List<Map<String, Object>>>
    controlsForAlert(
            @PathVariable String alertId
    ) {

        return ResponseEntity.ok(
                queryService.controlsForAlert(
                        alertId
                )
        );
    }


    // ============================================================
    // QUERY 5
    // ============================================================

    @GetMapping("/dependencies/{serviceName}")
    @Operation(
            summary = "Find dependency impact",
            description =
                    "Finds services that depend on the supplied service " +
                            "through one to three DEPENDS_ON relationships."
    )
    public ResponseEntity<List<Map<String, Object>>>
    dependencyImpact(
            @PathVariable String serviceName
    ) {

        return ResponseEntity.ok(
                queryService.dependencyImpact(
                        serviceName
                )
        );
    }


    // ============================================================
    // EVENTS CAUSING ALERT
    // ============================================================

    @GetMapping("/events/alert/{alertId}")
    @Operation(
            summary = "Find events causing an alert"
    )
    public ResponseEntity<List<Map<String, Object>>>
    eventsCausingAlert(
            @PathVariable String alertId
    ) {

        return ResponseEntity.ok(
                queryService.eventsCausingAlert(
                        alertId
                )
        );
    }


    // ============================================================
    // COMPLETE INVESTIGATION
    // ============================================================

    @GetMapping("/investigation/{alertId}")
    @Operation(
            summary = "Perform complete alert investigation",
            description =
                    "Traverses User -> Event -> Alert -> Threat -> Control."
    )
    public ResponseEntity<List<Map<String, Object>>>
    completeInvestigation(
            @PathVariable String alertId
    ) {

        return ResponseEntity.ok(
                queryService.completeAlertInvestigation(
                        alertId
                )
        );
    }


    // ============================================================
    // GRAPH OVERVIEW
    // ============================================================

    @GetMapping("/overview")
    @Operation(
            summary = "Get Neo4j graph overview"
    )
    public ResponseEntity<List<Map<String, Object>>>
    graphOverview() {

        return ResponseEntity.ok(
                queryService.graphOverview()
        );
    }


    // ============================================================
    // NEO4J HEALTH
    // ============================================================

    @GetMapping("/health")
    @Operation(
            summary = "Check Neo4j connection",
            description =
                    "Checks whether the SOC service can communicate with Neo4j."
    )
    @ApiResponses({
            @ApiResponse(
                    responseCode = "200",
                    description = "Neo4j is reachable"
            ),
            @ApiResponse(
                    responseCode = "503",
                    description = "Neo4j is unavailable"
            )
    })
    public ResponseEntity<String> health() {

        try {

            /*
             * IMPORTANT:
             *
             * The field is called graphService,
             * not neo4jGraphService.
             */
            graphService.verifyConnection();

            return ResponseEntity.ok(
                    "Neo4j connection is healthy"
            );

        } catch (Exception ex) {

            return ResponseEntity
                    .status(503)
                    .body(
                            "Neo4j connection failed"
                    );
        }
    }
}