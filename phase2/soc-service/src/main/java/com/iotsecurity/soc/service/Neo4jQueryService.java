package com.iotsecurity.soc.service;

import org.neo4j.driver.Driver;
import org.neo4j.driver.Record;
import org.neo4j.driver.Session;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.Map;

@Service
public class Neo4jQueryService {

    private final Driver driver;

    public Neo4jQueryService(Driver driver) {
        this.driver = driver;
    }


    // ============================================================
    // QUERY 1
    // ALERTS AFFECTING SERVICE
    // ============================================================

    public List<Map<String, Object>> alertsAffectingService(
            String serviceName
    ) {

        try (Session session = driver.session()) {

            return session.executeRead(tx ->
                    tx.run(
                                    """
                                    MATCH (a:Alert)
                                    WHERE a.affectedService = $serviceName
                                    RETURN a
                                    """,
                                    Map.of(
                                            "serviceName",
                                            serviceName
                                    )
                            )
                            .list()
                            .stream()
                            .map(Record::asMap)
                            .toList()
            );
        }
    }


    // ============================================================
    // QUERY 2
    // USERS LINKED TO HIGH-SEVERITY ALERTS
    // ============================================================

    public List<Map<String, Object>>
    usersLinkedToHighSeverityAlerts() {

        try (Session session = driver.session()) {

            return session.executeRead(tx ->
                    tx.run(
                                    """
                                    MATCH
                                        (u:User)
                                        -[:TRIGGERED]->
                                        (e:Event)
                                        -[:CREATED_ALERT]->
                                        (a:Alert)
        
                                    WHERE a.severity = 'HIGH'
        
                                    RETURN DISTINCT
                                        u.userId AS userId,
                                        a.alertId AS alertId,
                                        a.severity AS severity
                                    """
                            )
                            .list()
                            .stream()
                            .map(Record::asMap)
                            .toList()
            );
        }
    }


    // ============================================================
    // QUERY 3
    // THREATS LINKED TO SERVICE
    // ============================================================

    public List<Map<String, Object>>
    threatsLinkedToService(
            String serviceName
    ) {

        try (Session session = driver.session()) {

            return session.executeRead(tx ->
                    tx.run(
                                    """
                                    MATCH
                                        (t:Threat)
                                        -[:TARGETS]->
                                        (s:Service {
                                            name: $serviceName
                                        })
        
                                    RETURN
                                        t.threatId AS threatId,
                                        t.name AS name,
                                        t.description AS description,
                                        t.framework AS framework
                                    """,
                                    Map.of(
                                            "serviceName",
                                            serviceName
                                    )
                            )
                            .list()
                            .stream()
                            .map(Record::asMap)
                            .toList()
            );
        }
    }


    // ============================================================
    // QUERY 4
    // CONTROLS FOR ALERT
    // ============================================================

    public List<Map<String, Object>>
    controlsForAlert(
            String alertId
    ) {

        try (Session session = driver.session()) {

            return session.executeRead(tx ->
                    tx.run(
                                    """
                                    MATCH
                                        (a:Alert {
                                            alertId: $alertId
                                        })
                                        -[:INDICATES]->
                                        (t:Threat)
                                        <-[:MITIGATES]-
                                        (c:Control)
        
                                    RETURN
                                        a.alertId AS alert,
                                        t.threatId AS threatId,
                                        t.name AS threat,
                                        c.controlId AS controlId,
                                        c.name AS control
                                    """,
                                    Map.of(
                                            "alertId",
                                            alertId
                                    )
                            )
                            .list()
                            .stream()
                            .map(Record::asMap)
                            .toList()
            );
        }
    }


    // ============================================================
    // QUERY 5
    // DEPENDENCY IMPACT
    // ============================================================

    public List<Map<String, Object>>
    dependencyImpact(
            String serviceName
    ) {

        try (Session session = driver.session()) {

            return session.executeRead(tx ->
                    tx.run(
                                    """
                                    MATCH path =
                                        (s:Service {
                                            name: $serviceName
                                        })
                                        <-[:DEPENDS_ON*1..3]-
                                        (dependent:Service)
        
                                    RETURN path
                                    """,
                                    Map.of(
                                            "serviceName",
                                            serviceName
                                    )
                            )
                            .list()
                            .stream()
                            .map(Record::asMap)
                            .toList()
            );
        }
    }


    // ============================================================
    // ADDITIONAL QUERY
    // EVENTS CAUSING ALERT
    // ============================================================

    public List<Map<String, Object>>
    eventsCausingAlert(
            String alertId
    ) {

        try (Session session = driver.session()) {

            return session.executeRead(tx ->
                    tx.run(
                                    """
                                    MATCH
                                        (e:Event)
                                        -[:CREATED_ALERT]->
                                        (a:Alert {
                                            alertId: $alertId
                                        })
        
                                    RETURN
                                        e.eventId AS eventId,
                                        e.eventType AS eventType,
                                        e.severity AS severity,
                                        e.timestamp AS timestamp,
                                        e.sourceIp AS sourceIp,
                                        e.message AS message
                                    """,
                                    Map.of(
                                            "alertId",
                                            alertId
                                    )
                            )
                            .list()
                            .stream()
                            .map(Record::asMap)
                            .toList()
            );
        }
    }


    // ============================================================
    // COMPLETE INVESTIGATION
    // ============================================================

    public List<Map<String, Object>>
    completeAlertInvestigation(
            String alertId
    ) {

        try (Session session = driver.session()) {

            return session.executeRead(tx ->
                    tx.run(
                                    """
                                    MATCH
                                        (u:User)
                                        -[:TRIGGERED]->
                                        (e:Event)
                                        -[:CREATED_ALERT]->
                                        (a:Alert)
                                        -[:INDICATES]->
                                        (t:Threat)
                                        <-[:MITIGATES]-
                                        (c:Control)
        
                                    WHERE a.alertId = $alertId
        
                                    RETURN
                                        u.userId AS userId,
        
                                        e.eventId AS eventId,
                                        e.eventType AS eventType,
                                        e.severity AS eventSeverity,
                                        e.timestamp AS eventTimestamp,
        
                                        a.alertId AS alertId,
                                        a.ruleName AS ruleName,
                                        a.severity AS alertSeverity,
                                        a.affectedService AS affectedService,
                                        a.eventCount AS eventCount,
        
                                        t.threatId AS threatId,
                                        t.name AS threat,
                                        t.framework AS framework,
        
                                        c.controlId AS controlId,
                                        c.name AS control
                                    """,
                                    Map.of(
                                            "alertId",
                                            alertId
                                    )
                            )
                            .list()
                            .stream()
                            .map(Record::asMap)
                            .toList()
            );
        }
    }


    // ============================================================
    // GRAPH OVERVIEW
    // ============================================================

    public List<Map<String, Object>>
    graphOverview() {

        try (Session session = driver.session()) {

            return session.executeRead(tx ->
                    tx.run(
                                    """
                                    MATCH (n)
                                    RETURN
                                        labels(n) AS labels,
                                        count(n) AS count
                                    ORDER BY labels
                                    """
                            )
                            .list()
                            .stream()
                            .map(Record::asMap)
                            .toList()
            );
        }
    }
}