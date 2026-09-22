package com.iotsecurity.soc.controller;

import com.iotsecurity.soc.service.ThreatKnowledgeService;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.tags.Tag;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/soc/knowledge")
@Tag(
        name = "Security Knowledge",
        description = "Security knowledge graph management"
)
@SecurityRequirement(name = "bearerAuth")
public class KnowledgeGraphController {

    private final ThreatKnowledgeService
            threatKnowledgeService;

    public KnowledgeGraphController(
            ThreatKnowledgeService threatKnowledgeService
    ) {
        this.threatKnowledgeService =
                threatKnowledgeService;
    }

    @Operation(
            summary = "Initialize security knowledge",
            description =
                    "Creates the MITRE ATT&CK threat, vulnerability, controls and response procedures."
    )
    @PostMapping("/initialize")
    public ResponseEntity<String> initialize() {

        threatKnowledgeService
                .createBruteForceKnowledge();

        threatKnowledgeService
                .createAuthenticationVulnerability();

        threatKnowledgeService
                .connectThreatToVulnerability();

        threatKnowledgeService
                .createControls();

        threatKnowledgeService
                .connectControlsToThreat();

        threatKnowledgeService
                .createResponseProcedures();

        threatKnowledgeService
                .connectProceduresToThreat();

        return ResponseEntity.ok(
                "Security knowledge initialized successfully."
        );
    }
}