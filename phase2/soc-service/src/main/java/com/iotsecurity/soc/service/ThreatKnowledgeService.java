package com.iotsecurity.soc.service;

import org.neo4j.driver.Driver;
import org.neo4j.driver.Session;
import org.neo4j.driver.Values;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import org.springframework.stereotype.Service;

@Service
public class ThreatKnowledgeService {

    private static final Logger log =
            LoggerFactory.getLogger(
                    ThreatKnowledgeService.class
            );

    private final Driver driver;

    public ThreatKnowledgeService(Driver driver) {
        this.driver = driver;
    }

    public void connectThreatToVulnerability() {

        try (Session session = driver.session()) {

            session.executeWrite(tx -> {

                tx.run(
                        """
                        MATCH
                            (t:Threat {
                                threatId: $threatId
                            }),
                            (v:Vulnerability {
                                vulnerabilityId: $vulnerabilityId
                            })
                        MERGE (t)-[:EXPLOITS]->(v)
                        """,
                        Values.parameters(
                                "threatId",
                                "T1110",

                                "vulnerabilityId",
                                "VULN-AUTH-001"
                        )
                );

                return null;
            });

            log.info(
                    "KNOWLEDGE_RELATIONSHIP_CREATED threatId={} relationship={} vulnerabilityId={}",
                    "T1110",
                    "EXPLOITS",
                    "VULN-AUTH-001"
            );
        }
    }

    public void createAuthenticationVulnerability() {

        try (Session session = driver.session()) {

            session.executeWrite(tx -> {

                tx.run(
                        """
                        MERGE (v:Vulnerability {
                            vulnerabilityId: $vulnerabilityId
                        })
                        SET
                            v.name = $name,
                            v.description = $description
                        """,
                        Values.parameters(
                                "vulnerabilityId",
                                "VULN-AUTH-001",

                                "name",
                                "Weak Authentication Protection",

                                "description",
                                "Insufficient protection against repeated authentication attempts."
                        )
                );

                return null;
            });

            log.info(
                    "KNOWLEDGE_VULNERABILITY_CREATED vulnerabilityId={} name={}",
                    "VULN-AUTH-001",
                    "Weak Authentication Protection"
            );
        }
    }

    public void createBruteForceKnowledge() {

        try (Session session = driver.session()) {

            session.executeWrite(tx -> {

                tx.run(
                        """
                        MERGE (t:Threat {
                            threatId: $threatId
                        })
                        SET
                            t.name = $name,
                            t.framework = $framework
                        """,
                        Values.parameters(
                                "threatId", "T1110",
                                "name", "Brute Force",
                                "framework", "MITRE ATT&CK"
                        )
                );

                return null;
            });

            log.info(
                    "KNOWLEDGE_THREAT_CREATED threatId={} name={} framework={}",
                    "T1110",
                    "Brute Force",
                    "MITRE ATT&CK"
            );
        }
    }

    public void createControls() {

        try (Session session = driver.session()) {

            session.executeWrite(tx -> {

                tx.run(
                        """
                        UNWIND $controls AS control
        
                        MERGE (c:Control {
                            controlId: control.controlId
                        })
        
                        SET c.name = control.name
                        """,
                        Values.parameters(
                                "controls",
                                java.util.List.of(
                                        java.util.Map.of(
                                                "controlId", "CTRL-001",
                                                "name", "Account Lockout"
                                        ),
                                        java.util.Map.of(
                                                "controlId", "CTRL-002",
                                                "name", "Multi-Factor Authentication"
                                        ),
                                        java.util.Map.of(
                                                "controlId", "CTRL-003",
                                                "name", "Password Reset"
                                        ),
                                        java.util.Map.of(
                                                "controlId", "CTRL-004",
                                                "name", "IP Blocking"
                                        ),
                                        java.util.Map.of(
                                                "controlId", "CTRL-005",
                                                "name", "Rate Limiting"
                                        )
                                )
                        )
                );

                return null;
            });

            log.info(
                    "KNOWLEDGE_CONTROLS_CREATED count={}",
                    5
            );
        }
    }

    public void connectControlsToThreat() {

        try (Session session = driver.session()) {

            session.executeWrite(tx -> {

                tx.run(
                        """
                        MATCH
                            (t:Threat {
                                threatId: $threatId
                            })
        
                        MATCH
                            (c1:Control {
                                controlId: 'CTRL-001'
                            }),
                            (c2:Control {
                                controlId: 'CTRL-002'
                            }),
                            (c3:Control {
                                controlId: 'CTRL-003'
                            }),
                            (c4:Control {
                                controlId: 'CTRL-004'
                            }),
                            (c5:Control {
                                controlId: 'CTRL-005'
                            })
        
                        MERGE (c1)-[:MITIGATES]->(t)
                        MERGE (c2)-[:MITIGATES]->(t)
                        MERGE (c3)-[:MITIGATES]->(t)
                        MERGE (c4)-[:MITIGATES]->(t)
                        MERGE (c5)-[:MITIGATES]->(t)
                        """,
                        Values.parameters(
                                "threatId",
                                "T1110"
                        )
                );

                return null;
            });

            log.info(
                    "KNOWLEDGE_CONTROL_RELATIONSHIPS_CREATED threatId={}",
                    "T1110"
            );
        }
    }

    public void createResponseProcedures() {

        try (Session session = driver.session()) {

            session.executeWrite(tx -> {

                tx.run(
                        """
                        UNWIND $documents AS document
        
                        MERGE (d:Document {
                            documentId: document.documentId
                        })
        
                        SET
                            d.name = document.name,
                            d.type = document.type
                        """,
                        Values.parameters(
                                "documents",
                                java.util.List.of(
                                        java.util.Map.of(
                                                "documentId", "PROC-001",
                                                "name", "Password Reset Procedure",
                                                "type", "Procedure"
                                        ),
                                        java.util.Map.of(
                                                "documentId", "PROC-002",
                                                "name", "Incident Response Procedure",
                                                "type", "Procedure"
                                        ),
                                        java.util.Map.of(
                                                "documentId", "PROC-003",
                                                "name", "Account Lockout Procedure",
                                                "type", "Procedure"
                                        ),
                                        java.util.Map.of(
                                                "documentId", "PROC-004",
                                                "name", "IP Blocking Procedure",
                                                "type", "Procedure"
                                        )
                                )
                        )
                );

                return null;
            });

            log.info(
                    "KNOWLEDGE_RESPONSE_PROCEDURES_CREATED count={}",
                    4
            );
        }
    }

    public void connectProceduresToThreat() {

        try (Session session = driver.session()) {

            session.executeWrite(tx -> {

                tx.run(
                        """
                        MATCH
                            (t:Threat {
                                threatId: $threatId
                            })
        
                        MATCH
                            (d1:Document {
                                documentId: 'PROC-001'
                            }),
                            (d2:Document {
                                documentId: 'PROC-002'
                            }),
                            (d3:Document {
                                documentId: 'PROC-003'
                            }),
                            (d4:Document {
                                documentId: 'PROC-004'
                            })
        
                        MERGE (d1)-[:SUPPORTS_RESPONSE_TO]->(t)
                        MERGE (d2)-[:SUPPORTS_RESPONSE_TO]->(t)
                        MERGE (d3)-[:SUPPORTS_RESPONSE_TO]->(t)
                        MERGE (d4)-[:SUPPORTS_RESPONSE_TO]->(t)
                        """,
                        Values.parameters(
                                "threatId",
                                "T1110"
                        )
                );

                return null;
            });

            log.info(
                    "KNOWLEDGE_PROCEDURE_RELATIONSHIPS_CREATED threatId={}",
                    "T1110"
            );
        }
    }
}