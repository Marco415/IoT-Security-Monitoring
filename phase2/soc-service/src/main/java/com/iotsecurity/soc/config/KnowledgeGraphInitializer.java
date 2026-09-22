package com.iotsecurity.soc.config;

import com.iotsecurity.soc.service.ThreatKnowledgeService;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import org.springframework.boot.CommandLineRunner;
import org.springframework.stereotype.Component;

@Component
public class KnowledgeGraphInitializer
        implements CommandLineRunner {

    private static final Logger log =
            LoggerFactory.getLogger(
                    KnowledgeGraphInitializer.class
            );

    private final ThreatKnowledgeService
            threatKnowledgeService;

    public KnowledgeGraphInitializer(
            ThreatKnowledgeService threatKnowledgeService
    ) {
        this.threatKnowledgeService =
                threatKnowledgeService;
    }

    @Override
    public void run(String... args) {

        log.info(
                "KNOWLEDGE_GRAPH_INITIALIZATION_STARTED"
        );

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

        log.info(
                "KNOWLEDGE_GRAPH_INITIALIZATION_COMPLETED"
        );
    }
}