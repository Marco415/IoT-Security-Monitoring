package com.iotsecurity.soc.service;

import jakarta.annotation.PreDestroy;
import org.neo4j.driver.Driver;
import org.neo4j.driver.Session;
import org.neo4j.driver.TransactionContext;
import org.neo4j.driver.Values;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
public class Neo4jGraphService {

    private static final Logger log =
            LoggerFactory.getLogger(Neo4jGraphService.class);

    private final Driver driver;

    public Neo4jGraphService(Driver driver) {
        this.driver = driver;
    }


    // ============================================================
    // INITIALIZATION
    // ============================================================

    /**
     * Initializes the static security knowledge graph.
     *
     * Creates:
     *
     * Threat:
     *     T1110 - Brute Force
     *
     * Service:
     *     auth-service
     *
     * Controls:
     *     Account Lockout
     *     MFA
     *     Password Reset
     *
     * Relationships:
     *
     *     Threat -[:TARGETS]-> Service
     *     Control -[:MITIGATES]-> Threat
     */
    public void initializeGraph() {

        try (Session session = driver.session()) {

            session.executeWrite(tx -> {

                // ------------------------------------------------
                // Threat
                // ------------------------------------------------

                tx.run(
                        """
                        MERGE (t:Threat {
                            threatId: 'T1110'
                        })
                        SET
                            t.name = 'Brute Force',
                            t.description =
                                'Repeated authentication attempts against an account',
                            t.framework = 'MITRE ATT&CK'
                        """
                );


                // ------------------------------------------------
                // Authentication service
                // ------------------------------------------------

                tx.run(
                        """
                        MERGE (s:Service {
                            name: 'auth-service'
                        })
                        SET
                            s.description =
                                'Authentication microservice'
                        """
                );


                // ------------------------------------------------
                // Threat -> Service
                // ------------------------------------------------

                tx.run(
                        """
                        MATCH (t:Threat {
                            threatId: 'T1110'
                        })

                        MATCH (s:Service {
                            name: 'auth-service'
                        })

                        MERGE (t)-[:TARGETS]->(s)
                        """
                );


                // ------------------------------------------------
                // Controls
                // ------------------------------------------------

                createControl(
                        tx,
                        "CTRL-ACCOUNT-LOCKOUT",
                        "Account Lockout",
                        "Temporarily locks an account after repeated failed authentication attempts."
                );

                createControl(
                        tx,
                        "CTRL-MFA",
                        "MFA",
                        "Requires an additional authentication factor."
                );

                createControl(
                        tx,
                        "CTRL-PASSWORD-RESET",
                        "Password Reset",
                        "Allows a compromised or suspected compromised password to be replaced."
                );


                // ------------------------------------------------
                // Controls -> Threat
                // ------------------------------------------------

                tx.run(
                        """
                        MATCH (t:Threat {
                            threatId: 'T1110'
                        })

                        MATCH (c:Control)

                        WHERE c.controlId IN [
                            'CTRL-ACCOUNT-LOCKOUT',
                            'CTRL-MFA',
                            'CTRL-PASSWORD-RESET'
                        ]

                        MERGE (c)-[:MITIGATES]->(t)
                        """
                );


                return null;
            });

            log.info(
                    "Neo4j security knowledge graph initialized successfully"
            );

        } catch (Exception ex) {

            log.error(
                    "Failed to initialize Neo4j security knowledge graph",
                    ex
            );

            throw ex;
        }
    }


    /**
     * Creates or updates a Control node.
     *
     * This method fixes the previous:
     *
     * Cannot resolve method 'createControl'
     */
    private void createControl(
            TransactionContext tx,
            String controlId,
            String name,
            String description
    ) {

        tx.run(
                """
                MERGE (c:Control {
                    controlId: $controlId
                })

                SET
                    c.name = $name,
                    c.description = $description
                """,
                Values.parameters(
                        "controlId", controlId,
                        "name", name,
                        "description", description
                )
        );
    }


    // ============================================================
    // CONNECTION
    // ============================================================

    /**
     * Verifies that the SOC service can communicate with Neo4j.
     */
    public void verifyConnection() {

        try (Session session = driver.session()) {

            session.executeRead(tx ->
                    tx.run("RETURN 1")
                            .single()
                            .get(0)
                            .asInt()
            );

            log.info(
                    "Neo4j connection verified successfully"
            );

        } catch (Exception ex) {

            log.error(
                    "Neo4j connection verification failed",
                    ex
            );

            throw ex;
        }
    }


    // ============================================================
    // USER
    // ============================================================

    /**
     * Creates or updates a User node.
     */
    public void upsertUser(
            String userId,
            String role
    ) {

        if (userId == null || userId.isBlank()) {
            return;
        }

        try (Session session = driver.session()) {

            session.executeWrite(tx -> {

                tx.run(
                        """
                        MERGE (u:User {
                            userId: $userId
                        })
                        """,
                        Values.parameters(
                                "userId", userId
                        )
                );

                if (role != null && !role.isBlank()) {

                    tx.run(
                            """
                            MERGE (r:Role {
                                name: $role
                            })

                            WITH r

                            MATCH (u:User {
                                userId: $userId
                            })

                            MERGE (u)-[:HAS_ROLE]->(r)
                            """,
                            Values.parameters(
                                    "userId", userId,
                                    "role", role
                            )
                    );
                }

                return null;
            });

            log.info(
                    "Neo4j user synchronized userId={} role={}",
                    userId,
                    role
            );

        } catch (Exception ex) {

            log.error(
                    "Failed to synchronize Neo4j user userId={} role={}",
                    userId,
                    role,
                    ex
            );

            throw ex;
        }
    }


    // ============================================================
    // EVENT
    // ============================================================

    /**
     * Creates or updates an Event node.
     */
    public void upsertEvent(
            String eventId,
            String timestamp,
            String eventType,
            String severity,
            String sourceIp,
            String message
    ) {

        if (eventId == null || eventId.isBlank()) {
            return;
        }

        try (Session session = driver.session()) {

            session.executeWrite(tx -> {

                tx.run(
                        """
                        MERGE (e:Event {
                            eventId: $eventId
                        })

                        SET
                            e.timestamp = $timestamp,
                            e.eventType = $eventType,
                            e.severity = $severity,
                            e.sourceIp = $sourceIp,
                            e.message = $message
                        """,
                        Values.parameters(
                                "eventId", eventId,
                                "timestamp", timestamp,
                                "eventType", eventType,
                                "severity", severity,
                                "sourceIp", sourceIp,
                                "message", message
                        )
                );

                return null;
            });

            log.info(
                    "Neo4j event synchronized eventId={} eventType={} severity={}",
                    eventId,
                    eventType,
                    severity
            );

        } catch (Exception ex) {

            log.error(
                    "Failed to synchronize Neo4j event eventId={}",
                    eventId,
                    ex
            );

            throw ex;
        }
    }


    // ============================================================
    // EVENT -> SERVICE
    // ============================================================

    /**
     * Links an event to the service that generated it.
     */
    public void linkEventToService(
            String eventId,
            String serviceName
    ) {

        if (eventId == null ||
                eventId.isBlank() ||
                serviceName == null ||
                serviceName.isBlank()) {

            return;
        }

        try (Session session = driver.session()) {

            session.executeWrite(tx -> {

                tx.run(
                        """
                        MERGE (e:Event {
                            eventId: $eventId
                        })

                        MERGE (s:Service {
                            name: $serviceName
                        })

                        MERGE (e)-[:GENERATED_BY]->(s)
                        """,
                        Values.parameters(
                                "eventId", eventId,
                                "serviceName", serviceName
                        )
                );

                return null;
            });

            log.info(
                    "Neo4j event linked to service eventId={} serviceName={}",
                    eventId,
                    serviceName
            );

        } catch (Exception ex) {

            log.error(
                    "Failed to link Neo4j event to service " +
                            "eventId={} serviceName={}",
                    eventId,
                    serviceName,
                    ex
            );

            throw ex;
        }
    }


    // ============================================================
    // EVENT -> USER
    // ============================================================

    /**
     * Links an event to a user.
     *
     * User TRIGGERED Event
     */
    public void linkEventToUser(
            String eventId,
            String userId
    ) {

        if (eventId == null ||
                eventId.isBlank() ||
                userId == null ||
                userId.isBlank()) {

            return;
        }

        try (Session session = driver.session()) {

            session.executeWrite(tx -> {

                tx.run(
                        """
                        MERGE (u:User {
                            userId: $userId
                        })

                        MERGE (e:Event {
                            eventId: $eventId
                        })

                        MERGE (u)-[:TRIGGERED]->(e)
                        """,
                        Values.parameters(
                                "userId", userId,
                                "eventId", eventId
                        )
                );

                return null;
            });

            log.info(
                    "Neo4j event linked to user eventId={} userId={}",
                    eventId,
                    userId
            );

        } catch (Exception ex) {

            log.error(
                    "Failed to link Neo4j event to user " +
                            "eventId={} userId={}",
                    eventId,
                    userId,
                    ex
            );

            throw ex;
        }
    }


    // ============================================================
    // COMPLETE EVENT SYNCHRONIZATION
    // ============================================================

    /**
     * Synchronizes a complete SOC event.
     */
    public void synchronizeEvent(
            String eventId,
            String timestamp,
            String serviceName,
            String eventType,
            String severity,
            String userId,
            String sourceIp,
            String message
    ) {

        upsertEvent(
                eventId,
                timestamp,
                eventType,
                severity,
                sourceIp,
                message
        );

        if (serviceName != null &&
                !serviceName.isBlank()) {

            linkEventToService(
                    eventId,
                    serviceName
            );
        }

        if (userId != null &&
                !userId.isBlank()) {

            linkEventToUser(
                    eventId,
                    userId
            );
        }

        log.info(
                "Neo4j event synchronization complete " +
                        "eventId={} serviceName={} userId={}",
                eventId,
                serviceName,
                userId
        );
    }


    // ============================================================
    // ALERT
    // ============================================================

    /**
     * Creates or updates an Alert node.
     */
    public void upsertAlert(
            String alertId,
            String timestamp,
            String ruleName,
            String severity,
            String userId,
            String sourceIp,
            String serviceName,
            int eventCount,
            String message
    ) {

        if (alertId == null || alertId.isBlank()) {
            return;
        }

        try (Session session = driver.session()) {

            session.executeWrite(tx -> {

                tx.run(
                        """
                        MERGE (a:Alert {
                            alertId: $alertId
                        })

                        SET
                            a.timestamp = $timestamp,
                            a.ruleName = $ruleName,
                            a.severity = $severity,
                            a.userId = $userId,
                            a.sourceIp = $sourceIp,
                            a.affectedService = $serviceName,
                            a.eventCount = $eventCount,
                            a.description = $message
                        """,
                        Values.parameters(
                                "alertId", alertId,
                                "timestamp", timestamp,
                                "ruleName", ruleName,
                                "severity", severity,
                                "userId", userId,
                                "sourceIp", sourceIp,
                                "serviceName", serviceName,
                                "eventCount", eventCount,
                                "message", message
                        )
                );

                return null;
            });

            log.warn(
                    "Neo4j alert synchronized " +
                            "alertId={} ruleName={} severity={} eventCount={}",
                    alertId,
                    ruleName,
                    severity,
                    eventCount
            );

        } catch (Exception ex) {

            log.error(
                    "Failed to synchronize Neo4j alert alertId={}",
                    alertId,
                    ex
            );

            throw ex;
        }
    }


    // ============================================================
    // ALERT -> EVENT
    // ============================================================

    /**
     * Links an Event to an Alert.
     *
     * Event CREATED_ALERT Alert
     */
    public void linkAlertToEvent(
            String alertId,
            String eventId
    ) {

        if (alertId == null ||
                alertId.isBlank() ||
                eventId == null ||
                eventId.isBlank()) {

            return;
        }

        try (Session session = driver.session()) {

            session.executeWrite(tx -> {

                tx.run(
                        """
                        MERGE (a:Alert {
                            alertId: $alertId
                        })

                        MERGE (e:Event {
                            eventId: $eventId
                        })

                        MERGE (e)-[:CREATED_ALERT]->(a)
                        """,
                        Values.parameters(
                                "alertId", alertId,
                                "eventId", eventId
                        )
                );

                return null;
            });

            log.info(
                    "Neo4j alert linked to event " +
                            "alertId={} eventId={}",
                    alertId,
                    eventId
            );

        } catch (Exception ex) {

            log.error(
                    "Failed to link Neo4j alert to event " +
                            "alertId={} eventId={}",
                    alertId,
                    eventId,
                    ex
            );

            throw ex;
        }
    }


    // ============================================================
    // ALERT -> USER
    // ============================================================

    /**
     * Links an alert to the affected user.
     */
    public void linkAlertToUser(
            String alertId,
            String userId
    ) {

        if (alertId == null ||
                alertId.isBlank() ||
                userId == null ||
                userId.isBlank()) {

            return;
        }

        try (Session session = driver.session()) {

            session.executeWrite(tx -> {

                tx.run(
                        """
                        MERGE (a:Alert {
                            alertId: $alertId
                        })

                        MERGE (u:User {
                            userId: $userId
                        })

                        MERGE (a)-[:AFFECTS_USER]->(u)
                        """,
                        Values.parameters(
                                "alertId", alertId,
                                "userId", userId
                        )
                );

                return null;
            });

            log.info(
                    "Neo4j alert linked to user " +
                            "alertId={} userId={}",
                    alertId,
                    userId
            );

        } catch (Exception ex) {

            log.error(
                    "Failed to link Neo4j alert to user " +
                            "alertId={} userId={}",
                    alertId,
                    userId,
                    ex
            );

            throw ex;
        }
    }


    // ============================================================
    // ALERT -> SERVICE
    // ============================================================

    /**
     * Links an alert to the affected service.
     */
    public void linkAlertToService(
            String alertId,
            String serviceName
    ) {

        if (alertId == null ||
                alertId.isBlank() ||
                serviceName == null ||
                serviceName.isBlank()) {

            return;
        }

        try (Session session = driver.session()) {

            session.executeWrite(tx -> {

                tx.run(
                        """
                        MERGE (a:Alert {
                            alertId: $alertId
                        })

                        MERGE (s:Service {
                            name: $serviceName
                        })

                        MERGE (a)-[:AFFECTS]->(s)
                        """,
                        Values.parameters(
                                "alertId", alertId,
                                "serviceName", serviceName
                        )
                );

                return null;
            });

            log.info(
                    "Neo4j alert linked to service " +
                            "alertId={} serviceName={}",
                    alertId,
                    serviceName
            );

        } catch (Exception ex) {

            log.error(
                    "Failed to link Neo4j alert to service " +
                            "alertId={} serviceName={}",
                    alertId,
                    serviceName,
                    ex
            );

            throw ex;
        }
    }


    // ============================================================
    // THREAT
    // ============================================================

    /**
     * Creates or updates a Threat node.
     */
    public void ensureThreat(
            String threatId,
            String name,
            String description
    ) {

        if (threatId == null ||
                threatId.isBlank()) {

            return;
        }

        try (Session session = driver.session()) {

            session.executeWrite(tx -> {

                tx.run(
                        """
                        MERGE (t:Threat {
                            threatId: $threatId
                        })

                        SET
                            t.name = $name,
                            t.description = $description,
                            t.framework = 'MITRE ATT&CK'
                        """,
                        Values.parameters(
                                "threatId", threatId,
                                "name", name,
                                "description", description
                        )
                );

                return null;
            });

            log.info(
                    "Neo4j threat synchronized " +
                            "threatId={} name={}",
                    threatId,
                    name
            );

        } catch (Exception ex) {

            log.error(
                    "Failed to synchronize Neo4j threat " +
                            "threatId={}",
                    threatId,
                    ex
            );

            throw ex;
        }
    }


    // ============================================================
    // ALERT -> THREAT
    // ============================================================

    /**
     * Links an Alert to a Threat.
     *
     * Alert INDICATES Threat
     */
    public void linkAlertToThreat(
            String alertId,
            String threatId
    ) {

        if (alertId == null ||
                alertId.isBlank() ||
                threatId == null ||
                threatId.isBlank()) {

            return;
        }

        try (Session session = driver.session()) {

            session.executeWrite(tx -> {

                tx.run(
                        """
                        MERGE (a:Alert {
                            alertId: $alertId
                        })

                        MERGE (t:Threat {
                            threatId: $threatId
                        })

                        MERGE (a)-[:INDICATES]->(t)
                        """,
                        Values.parameters(
                                "alertId", alertId,
                                "threatId", threatId
                        )
                );

                return null;
            });

            log.info(
                    "Neo4j alert linked to threat " +
                            "alertId={} threatId={}",
                    alertId,
                    threatId
            );

        } catch (Exception ex) {

            log.error(
                    "Failed to link alert to threat " +
                            "alertId={} threatId={}",
                    alertId,
                    threatId,
                    ex
            );

            throw ex;
        }
    }


    // ============================================================
    // THREAT -> SERVICE
    // ============================================================

    /**
     * Links a Threat to a Service.
     *
     * Threat TARGETS Service
     */
    public void linkThreatToService(
            String threatId,
            String serviceName
    ) {

        if (threatId == null ||
                threatId.isBlank() ||
                serviceName == null ||
                serviceName.isBlank()) {

            return;
        }

        try (Session session = driver.session()) {

            session.executeWrite(tx -> {

                tx.run(
                        """
                        MERGE (t:Threat {
                            threatId: $threatId
                        })

                        MERGE (s:Service {
                            name: $serviceName
                        })

                        MERGE (t)-[:TARGETS]->(s)
                        """,
                        Values.parameters(
                                "threatId", threatId,
                                "serviceName", serviceName
                        )
                );

                return null;
            });

            log.info(
                    "Neo4j threat linked to service " +
                            "threatId={} serviceName={}",
                    threatId,
                    serviceName
            );

        } catch (Exception ex) {

            log.error(
                    "Failed to link threat to service " +
                            "threatId={} serviceName={}",
                    threatId,
                    serviceName,
                    ex
            );

            throw ex;
        }
    }


    // ============================================================
    // SERVICE DEPENDENCIES
    // ============================================================

    /**
     * Creates:
     *
     * serviceA -[:DEPENDS_ON]-> serviceB
     */
    public void createServiceDependency(
            String dependentService,
            String dependencyService
    ) {

        if (dependentService == null ||
                dependentService.isBlank() ||
                dependencyService == null ||
                dependencyService.isBlank()) {

            return;
        }

        try (Session session = driver.session()) {

            session.executeWrite(tx -> {

                tx.run(
                        """
                        MERGE (dependent:Service {
                            name: $dependentService
                        })

                        MERGE (dependency:Service {
                            name: $dependencyService
                        })

                        MERGE
                            (dependent)-[:DEPENDS_ON]->(dependency)
                        """,
                        Values.parameters(
                                "dependentService",
                                dependentService,

                                "dependencyService",
                                dependencyService
                        )
                );

                return null;
            });

            log.info(
                    "Neo4j service dependency created " +
                            "dependentService={} dependencyService={}",
                    dependentService,
                    dependencyService
            );

        } catch (Exception ex) {

            log.error(
                    "Failed to create service dependency " +
                            "dependentService={} dependencyService={}",
                    dependentService,
                    dependencyService,
                    ex
            );

            throw ex;
        }
    }


    // ============================================================
    // COMPLETE ALERT SYNCHRONIZATION
    // ============================================================

    /**
     * Synchronizes the alert currently produced by AlertService.
     *
     * This is retained for compatibility with your existing
     * AlertService.
     */
    public void synchronizeAlert(
            String alertId,
            String timestamp,
            String ruleName,
            String severity,
            String userId,
            String sourceIp,
            String serviceName,
            int eventCount,
            String message,
            String eventId
    ) {

        upsertAlert(
                alertId,
                timestamp,
                ruleName,
                severity,
                userId,
                sourceIp,
                serviceName,
                eventCount,
                message
        );

        if (eventId != null &&
                !eventId.isBlank()) {

            linkAlertToEvent(
                    alertId,
                    eventId
            );
        }

        if (userId != null &&
                !userId.isBlank()) {

            linkAlertToUser(
                    alertId,
                    userId
            );
        }

        if (serviceName != null &&
                !serviceName.isBlank()) {

            linkAlertToService(
                    alertId,
                    serviceName
            );
        }

        /*
         * MULTIPLE_FAILED_LOGINS is represented by
         * MITRE ATT&CK T1110 - Brute Force.
         */
        if ("MULTIPLE_FAILED_LOGINS".equalsIgnoreCase(ruleName)) {

            ensureThreat(
                    "T1110",
                    "Brute Force",
                    "Repeated authentication attempts against an account."
            );

            linkAlertToThreat(
                    alertId,
                    "T1110"
            );

            if (serviceName != null &&
                    !serviceName.isBlank()) {

                linkThreatToService(
                        "T1110",
                        serviceName
                );
            }
        }

        log.info(
                "Neo4j alert synchronization complete " +
                        "alertId={} eventId={} serviceName={} userId={}",
                alertId,
                eventId,
                serviceName,
                userId
        );
    }


    // ============================================================
    // COMPLETE FAILED-LOGIN GRAPH
    // ============================================================

    /**
     * Creates the complete failed-login graph in one Neo4j
     * transaction.
     *
     * Graph:
     *
     * User
     *   |
     *   | TRIGGERED
     *   v
     * Event 1
     * Event 2
     * Event 3
     *   |
     *   | CREATED_ALERT
     *   v
     * Alert
     *   |
     *   | INDICATES
     *   v
     * Threat T1110
     *   |
     *   | TARGETS
     *   v
     * auth-service
     *
     * Controls:
     *
     * Account Lockout
     * MFA
     * Password Reset
     *
     * all MITIGATES T1110.
     */
    public void createFailedLoginGraph(
            String username,
            List<String> eventIds,
            String alertId,
            String severity,
            String affectedService
    ) {

        if (username == null ||
                username.isBlank()) {

            throw new IllegalArgumentException(
                    "username must not be blank"
            );
        }

        if (eventIds == null ||
                eventIds.isEmpty()) {

            throw new IllegalArgumentException(
                    "At least one eventId is required"
            );
        }

        if (alertId == null ||
                alertId.isBlank()) {

            throw new IllegalArgumentException(
                    "alertId must not be blank"
            );
        }

        if (severity == null ||
                severity.isBlank()) {

            severity = "HIGH";
        }

        if (affectedService == null ||
                affectedService.isBlank()) {

            affectedService = "auth-service";
        }

        final String finalSeverity = severity;
        final String finalAffectedService = affectedService;

        try (Session session = driver.session()) {

            session.executeWrite(tx -> {

                // ------------------------------------------------
                // USER
                // ------------------------------------------------

                tx.run(
                        """
                        MERGE (u:User {
                            userId: $username
                        })
                        """,
                        Values.parameters(
                                "username", username
                        )
                );


                // ------------------------------------------------
                // SERVICE
                // ------------------------------------------------

                tx.run(
                        """
                        MERGE (s:Service {
                            name: $serviceName
                        })

                        SET s.description =
                            CASE
                                WHEN s.description IS NULL
                                THEN 'Microservice'
                                ELSE s.description
                            END
                        """,
                        Values.parameters(
                                "serviceName",
                                finalAffectedService
                        )
                );


                // ------------------------------------------------
                // THREAT
                // ------------------------------------------------

                tx.run(
                        """
                        MERGE (t:Threat {
                            threatId: 'T1110'
                        })

                        SET
                            t.name = 'Brute Force',
                            t.description =
                                'Repeated authentication attempts against an account',
                            t.framework = 'MITRE ATT&CK'
                        """
                );


                // ------------------------------------------------
                // THREAT -> SERVICE
                // ------------------------------------------------

                tx.run(
                        """
                        MATCH (t:Threat {
                            threatId: 'T1110'
                        })

                        MATCH (s:Service {
                            name: $serviceName
                        })

                        MERGE (t)-[:TARGETS]->(s)
                        """,
                        Values.parameters(
                                "serviceName",
                                finalAffectedService
                        )
                );


                // ------------------------------------------------
                // CONTROLS
                // ------------------------------------------------

                createControl(
                        tx,
                        "CTRL-ACCOUNT-LOCKOUT",
                        "Account Lockout",
                        "Temporarily locks an account after repeated failed authentication attempts."
                );

                createControl(
                        tx,
                        "CTRL-MFA",
                        "MFA",
                        "Requires an additional authentication factor."
                );

                createControl(
                        tx,
                        "CTRL-PASSWORD-RESET",
                        "Password Reset",
                        "Allows a suspected compromised password to be replaced."
                );


                // ------------------------------------------------
                // CONTROL -> THREAT
                // ------------------------------------------------

                tx.run(
                        """
                        MATCH (t:Threat {
                            threatId: 'T1110'
                        })

                        MATCH (c:Control)

                        WHERE c.controlId IN [
                            'CTRL-ACCOUNT-LOCKOUT',
                            'CTRL-MFA',
                            'CTRL-PASSWORD-RESET'
                        ]

                        MERGE (c)-[:MITIGATES]->(t)
                        """
                );


                // ------------------------------------------------
                // ALERT
                // ------------------------------------------------

                tx.run(
                        """
                        MERGE (a:Alert {
                            alertId: $alertId
                        })

                        SET
                            a.ruleName =
                                'MULTIPLE_FAILED_LOGINS',
                            a.severity =
                                $severity,
                            a.affectedService =
                                $serviceName,
                            a.eventCount =
                                $eventCount
                        """,
                        Values.parameters(
                                "alertId",
                                alertId,

                                "severity",
                                finalSeverity,

                                "serviceName",
                                finalAffectedService,

                                "eventCount",
                                eventIds.size()
                        )
                );


                // ------------------------------------------------
                // USER -> EVENTS -> ALERT
                // ------------------------------------------------

                for (String eventId : eventIds) {

                    if (eventId == null ||
                            eventId.isBlank()) {

                        continue;
                    }

                    tx.run(
                            """
                            MERGE (e:Event {
                                eventId: $eventId
                            })

                            SET
                                e.eventType = 'FAILED_LOGIN',
                                e.severity = $severity
                            """,
                            Values.parameters(
                                    "eventId",
                                    eventId,

                                    "severity",
                                    finalSeverity
                            )
                    );

                    tx.run(
                            """
                            MATCH (u:User {
                                userId: $username
                            })

                            MATCH (e:Event {
                                eventId: $eventId
                            })

                            MERGE (u)-[:TRIGGERED]->(e)
                            """,
                            Values.parameters(
                                    "username",
                                    username,

                                    "eventId",
                                    eventId
                            )
                    );

                    tx.run(
                            """
                            MATCH (e:Event {
                                eventId: $eventId
                            })

                            MATCH (a:Alert {
                                alertId: $alertId
                            })

                            MERGE (e)-[:CREATED_ALERT]->(a)
                            """,
                            Values.parameters(
                                    "eventId",
                                    eventId,

                                    "alertId",
                                    alertId
                            )
                    );
                }


                // ------------------------------------------------
                // ALERT -> THREAT
                // ------------------------------------------------

                tx.run(
                        """
                        MATCH (a:Alert {
                            alertId: $alertId
                        })

                        MATCH (t:Threat {
                            threatId: 'T1110'
                        })

                        MERGE (a)-[:INDICATES]->(t)
                        """,
                        Values.parameters(
                                "alertId",
                                alertId
                        )
                );


                // ------------------------------------------------
                // ALERT -> SERVICE
                // ------------------------------------------------

                tx.run(
                        """
                        MATCH (a:Alert {
                            alertId: $alertId
                        })

                        MATCH (s:Service {
                            name: $serviceName
                        })

                        MERGE (a)-[:AFFECTS]->(s)
                        """,
                        Values.parameters(
                                "alertId",
                                alertId,

                                "serviceName",
                                finalAffectedService
                        )
                );


                return null;
            });

            log.warn(
                    "Complete failed-login Neo4j graph created " +
                            "username={} alertId={} eventCount={} " +
                            "severity={} affectedService={}",
                    username,
                    alertId,
                    eventIds.size(),
                    finalSeverity,
                    finalAffectedService
            );

        } catch (Exception ex) {

            log.error(
                    "Failed to create complete failed-login graph " +
                            "username={} alertId={}",
                    username,
                    alertId,
                    ex
            );

            throw ex;
        }
    }


    // ============================================================
    // SHUTDOWN
    // ============================================================

    @PreDestroy
    public void close() {

        if (driver != null) {

            driver.close();

            log.info(
                    "Neo4j driver closed"
            );
        }
    }
}