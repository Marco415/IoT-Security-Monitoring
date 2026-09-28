package com.iotsecurity.soc.service;

import com.iotsecurity.soc.model.SOCEvent;
import com.iotsecurity.soc.repository.SOCEventRepository;
import org.neo4j.driver.Driver;
import org.neo4j.driver.Session;
import org.neo4j.driver.Values;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;

import java.sql.Timestamp;
import java.util.List;
import java.util.Map;

@Service
public class Neo4jEntitySyncService {

    private static final Logger log =
            LoggerFactory.getLogger(Neo4jEntitySyncService.class);

    private final JdbcTemplate deviceJdbcTemplate;
    private final JdbcTemplate authJdbcTemplate;
    private final Driver neo4jDriver;
    private final SOCEventRepository socEventRepository;

    private final boolean enabled;

    public Neo4jEntitySyncService(
            @Qualifier("deviceJdbcTemplate")
            JdbcTemplate deviceJdbcTemplate,

            @Qualifier("authSourceJdbcTemplate")
            JdbcTemplate authJdbcTemplate,

            Driver neo4jDriver,

            SOCEventRepository socEventRepository,

            @Value("${soc.graph.entity-sync.enabled:true}")
            boolean enabled) {

        this.deviceJdbcTemplate = deviceJdbcTemplate;
        this.authJdbcTemplate = authJdbcTemplate;
        this.neo4jDriver = neo4jDriver;
        this.socEventRepository = socEventRepository;
        this.enabled = enabled;
    }

    /*
     * ============================================================
     * MAIN ENTITY SYNCHRONIZATION
     * ============================================================
     */

    @Scheduled(
            fixedDelayString = "${soc.graph.entity-sync.interval-ms:30000}",
            initialDelayString = "${soc.graph.entity-sync.initial-delay-ms:10000}"
    )
    public void synchronizeEntities() {

        if (!enabled) {
            return;
        }

        try {
            synchronizeDevices();
            synchronizeUsers();
            synchronizeSocEvents();

            log.info("Neo4j entity synchronization complete");

        } catch (Exception e) {
            log.error(
                    "Neo4j entity synchronization failed: {}",
                    e.getMessage(),
                    e
            );
        }
    }

    /*
     * ============================================================
     * DEVICES
     * ============================================================
     */

    private void synchronizeDevices() {

        String sql = """
                SELECT
                    id,
                    created_at,
                    device_id,
                    device_type,
                    ip_address,
                    location,
                    manufacturer,
                    name,
                    status,
                    updated_at
                FROM devices
                ORDER BY id
                """;

        List<Map<String, Object>> devices =
                deviceJdbcTemplate.queryForList(sql);

        if (devices.isEmpty()) {
            log.debug("No devices found for Neo4j synchronization");
            return;
        }

        try (Session session = neo4jDriver.session()) {

            for (Map<String, Object> device : devices) {
                upsertDevice(session, device);
            }
        }

        log.info(
                "Synchronized {} devices to Neo4j",
                devices.size()
        );
    }

    private void upsertDevice(
            Session session,
            Map<String, Object> device) {

        session.run(
                """
                MERGE (d:Device {
                    deviceId: $deviceId
                })
                SET
                    d.sourceId = $sourceId,
                    d.deviceType = $deviceType,
                    d.ipAddress = $ipAddress,
                    d.location = $location,
                    d.manufacturer = $manufacturer,
                    d.name = $name,
                    d.status = $status,
                    d.createdAt = $createdAt,
                    d.updatedAt = $updatedAt,
                    d.sourceSystem = 'device-service'

                WITH d

                MERGE (dt:DeviceType {
                    name: $deviceType
                })

                MERGE (d)-[:HAS_DEVICE_TYPE]->(dt)
                """,
                Values.parameters(
                        "deviceId",
                        device.get("device_id"),

                        "sourceId",
                        device.get("id"),

                        "deviceType",
                        device.get("device_type"),

                        "ipAddress",
                        device.get("ip_address"),

                        "location",
                        device.get("location"),

                        "manufacturer",
                        device.get("manufacturer"),

                        "name",
                        device.get("name"),

                        "status",
                        device.get("status"),

                        "createdAt",
                        toNeo4jTemporalValue(
                                device.get("created_at")
                        ),

                        "updatedAt",
                        toNeo4jTemporalValue(
                                device.get("updated_at")
                        )
                )
        );
    }

    /*
     * ============================================================
     * USERS
     * ============================================================
     *
     * The PostgreSQL auth.users table is the source of truth.
     *
     * Passwords are deliberately never copied to Neo4j.
     *
     * The graph representation is:
     *
     * User -> HAS_ROLE -> Role
     */

    private void synchronizeUsers() {

        String sql = """
                SELECT
                    id,
                    enabled,
                    role,
                    username
                FROM users
                ORDER BY id
                """;

        List<Map<String, Object>> users =
                authJdbcTemplate.queryForList(sql);

        try (Session session = neo4jDriver.session()) {

            /*
             * Remove obsolete User nodes that have no username.
             *
             * These are legacy graph nodes from the previous
             * manually-created graph structure.
             *
             * Their relationships are also removed because the
             * current auth database is the source of truth.
             */
            cleanupAnonymousUsers(session);

            for (Map<String, Object> user : users) {
                upsertUser(session, user);
            }

            /*
             * Remove the old role property representation.
             *
             * The role is now represented as:
             *
             * (User)-[:HAS_ROLE]->(Role)
             */
            session.run(
                    """
                    MATCH (u:User)
                    REMOVE u.role
                    """
            );
        }

        log.info(
                "Synchronized {} users to Neo4j",
                users.size()
        );
    }

    private void cleanupAnonymousUsers(
            Session session) {

        session.run(
                """
                MATCH (u:User)
                WHERE u.username IS NULL
                DETACH DELETE u
                """
        );

        log.debug(
                "Removed legacy anonymous User nodes from Neo4j"
        );
    }

    private void upsertUser(
            Session session,
            Map<String, Object> user) {

        session.run(
                """
                MERGE (u:User {
                    username: $username
                })
                SET
                    u.sourceId = $sourceId,
                    u.enabled = $enabled,
                    u.sourceSystem = 'auth-service'

                WITH u

                MERGE (r:Role {
                    name: $role
                })

                MERGE (u)-[:HAS_ROLE]->(r)

                WITH u, r

                MATCH (u)-[old:HAS_ROLE]->(other:Role)
                WHERE other <> r
                DELETE old
                """,
                Values.parameters(
                        "username",
                        user.get("username"),

                        "sourceId",
                        user.get("id"),

                        "enabled",
                        user.get("enabled"),

                        "role",
                        user.get("role")
                )
        );
    }

    /*
     * ============================================================
     * RELATIONSHIPS
     * ============================================================
     */

    @Scheduled(
            fixedDelayString = "${soc.graph.entity-sync.relationship-interval-ms:30000}",
            initialDelayString = "${soc.graph.entity-sync.relationship-initial-delay-ms:15000}"
    )
    public void synchronizeEntityRelationships() {

        if (!enabled) {
            return;
        }

        try (Session session = neo4jDriver.session()) {

            createDeviceEventRelationships(session);
            createUserEventRelationships(session);

            log.debug("Neo4j entity relationships synchronized");

        } catch (Exception e) {
            log.error(
                    "Neo4j entity relationship synchronization failed: {}",
                    e.getMessage(),
                    e
            );
        }
    }

    /*
     * Device -> Security Event
     *
     * Requires Event.deviceId to match Device.deviceId.
     */
    private void createDeviceEventRelationships(
            Session session) {

        session.run(
                """
                MATCH (d:Device)
                MATCH (e:Event)
                WHERE e.deviceId IS NOT NULL
                  AND trim(e.deviceId) <> ''
                  AND d.deviceId = e.deviceId

                MERGE (d)-[:HAS_SECURITY_EVENT]->(e)
                """
        );
    }

    /*
     * User -> Authentication Event
     *
     * Requires Event.username to match User.username.
     */
    private void createUserEventRelationships(
            Session session) {

        session.run(
                """
                MATCH (u:User)
                MATCH (e:Event)
                WHERE e.username IS NOT NULL
                  AND trim(e.username) <> ''
                  AND u.username = e.username
    
                MERGE (u)-[:TRIGGERED]->(e)
                """
        );
    }

    /*
     * ============================================================
     * TIMESTAMP CONVERSION
     * ============================================================
     */

    private Object toNeo4jTemporalValue(Object value) {

        if (value == null) {
            return null;
        }

        if (value instanceof Timestamp timestamp) {
            return timestamp.toLocalDateTime();
        }

        return value;
    }

    private void synchronizeSocEvents() {

        List<SOCEvent> events =
                socEventRepository.findAll();

        if (events.isEmpty()) {
            log.debug("No SOC events found for Neo4j synchronization");
            return;
        }

        try (Session session = neo4jDriver.session()) {

            for (SOCEvent event : events) {

                session.run(
                        """
                        MATCH (e:Event {
                            eventId: $eventId
                        })
                        SET
                            e.timestamp = $timestamp,
                            e.eventType = $eventType,
                            e.severity = $severity,
                            e.sourceIp = $sourceIp,
                            e.message = $message,
                            e.username = $username,
                            e.deviceId = $deviceId
                        """,
                        Values.parameters(
                                "eventId",
                                event.getEventId().toString(),

                                "timestamp",
                                event.getTimestamp() != null
                                        ? event.getTimestamp().toString()
                                        : null,

                                "eventType",
                                event.getEventType(),

                                "severity",
                                event.getSeverity(),

                                "sourceIp",
                                event.getSourceIp(),

                                "message",
                                event.getMessage(),

                                "username",
                                event.getUserId(),

                                "deviceId",
                                event.getAffectedEntity()
                        )
                );
            }
        }

        log.info(
                "Backfilled {} SOC events into Neo4j",
                events.size()
        );
    }
}