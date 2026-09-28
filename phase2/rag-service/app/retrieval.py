from app.neo4j_client import Neo4jClient


class GraphRetriever:

    def __init__(
        self,
        neo4j_client: Neo4jClient
    ):
        self.neo4j = neo4j_client

    # =========================================================
    # ALERT INVESTIGATION
    # =========================================================

    def retrieve_alert_investigation(
        self,
        alert_id: str
    ):

        query = """
        MATCH (alert:Alert {alertId: $alert_id})

        OPTIONAL MATCH
            (event:Event)-[created:CREATED_ALERT]->(alert)

        OPTIONAL MATCH
            (user:User)-[triggered:TRIGGERED]->(event)

        OPTIONAL MATCH
            (alert)-[indicates:INDICATES]->(threat:Threat)

        OPTIONAL MATCH
            (control:Control)-[mitigates:MITIGATES]->(threat)

        RETURN
            alert,

            collect(DISTINCT event) AS events,

            collect(DISTINCT user) AS users,

            collect(DISTINCT threat) AS threats,

            collect(DISTINCT control) AS controls,

            collect(DISTINCT {
                source: event.eventId,
                relationship: type(created),
                target: alert.alertId
            }) AS event_alert_relationships,

            collect(DISTINCT {
                source: user.userId,
                relationship: type(triggered),
                target: event.eventId
            }) AS user_event_relationships,

            collect(DISTINCT {
                source: alert.alertId,
                relationship: type(indicates),
                target: threat.name
            }) AS alert_threat_relationships,

            collect(DISTINCT {
                source: control.name,
                relationship: type(mitigates),
                target: threat.name
            }) AS control_threat_relationships
        """

        return self.neo4j.run_query(
            query,
            {
                "alert_id": alert_id
            }
        )

    # =========================================================
    # THREAT CONTROLS
    # =========================================================

    def retrieve_threat_controls(
        self,
        alert_id: str
    ):

        query = """
        MATCH
            (alert:Alert {alertId: $alert_id})
            -[indicates:INDICATES]->
            (threat:Threat)

        OPTIONAL MATCH
            (control:Control)
            -[mitigates:MITIGATES]->
            (threat)

        RETURN
            alert,
            threat,

            collect(DISTINCT control) AS controls,

            collect(DISTINCT {
                source: alert.alertId,
                relationship: type(indicates),
                target: threat.name
            }) AS alert_threat_relationships,

            collect(DISTINCT {
                source: control.name,
                relationship: type(mitigates),
                target: threat.name
            }) AS control_threat_relationships
        """

        return self.neo4j.run_query(
            query,
            {
                "alert_id": alert_id
            }
        )

    # =========================================================
    # SERVICE DEPENDENCIES
    # =========================================================

    def retrieve_service_dependencies(
        self,
        service_name: str
    ):

        query = """
        MATCH
            (failed:Service {name: $service_name})

        OPTIONAL MATCH path =
            (affected:Service)
            -[:DEPENDS_ON*1..5]->
            (failed)

        RETURN
            failed,

            collect(DISTINCT affected)
                AS affected_services,

            [p IN collect(path) |
                [r IN relationships(p) |
                    {
                        source: startNode(r).name,
                        relationship: type(r),
                        target: endNode(r).name
                    }
                ]
            ] AS dependency_relationships
        """

        return self.neo4j.run_query(
            query,
            {
                "service_name": service_name
            }
        )

    # =========================================================
    # USER EVENTS
    # =========================================================

    def retrieve_user_events(
        self,
        user_id: str
    ):

        query = """
        MATCH
            (user:User {userId: $user_id})
            -[triggered:TRIGGERED]->
            (event:Event)

        RETURN
            user,

            collect(DISTINCT event)
                AS events,

            collect(DISTINCT {
                source: user.userId,
                relationship: type(triggered),
                target: event.eventId
            }) AS user_event_relationships
        """

        return self.neo4j.run_query(
            query,
            {
                "user_id": user_id
            }
        )

    # =========================================================
    # USER ALERTS
    # =========================================================

    def retrieve_user_alerts(
        self,
        user_id: str
    ):

        query = """
        MATCH
            (user:User {userId: $user_id})
            -[:TRIGGERED]->
            (event:Event)
            -[:CREATED_ALERT]->
            (alert:Alert)

        RETURN
            user,

            collect(DISTINCT event)
                AS events,

            collect(DISTINCT alert)
                AS alerts,

            collect(DISTINCT {
                source: user.userId,
                relationship: "TRIGGERED",
                target: event.eventId
            }) AS user_event_relationships,

            collect(DISTINCT {
                source: event.eventId,
                relationship: "CREATED_ALERT",
                target: alert.alertId
            }) AS event_alert_relationships
        """

        return self.neo4j.run_query(
            query,
            {
                "user_id": user_id
            }
        )

    # =========================================================
    # EVENT INVESTIGATION
    # =========================================================

    def retrieve_event_investigation(
        self,
        event_id: str
    ):

        query = """
        MATCH
            (event:Event {eventId: $event_id})

        OPTIONAL MATCH
            (user:User)-[triggered:TRIGGERED]->
            (event)

        OPTIONAL MATCH
            (event)-[created:CREATED_ALERT]->
            (alert:Alert)

        OPTIONAL MATCH
            (alert)-[indicates:INDICATES]->
            (threat:Threat)

        RETURN
            event,

            collect(DISTINCT user)
                AS users,

            collect(DISTINCT alert)
                AS alerts,

            collect(DISTINCT threat)
                AS threats,

            collect(DISTINCT {
                source: user.userId,
                relationship: type(triggered),
                target: event.eventId
            }) AS user_event_relationships,

            collect(DISTINCT {
                source: event.eventId,
                relationship: type(created),
                target: alert.alertId
            }) AS event_alert_relationships,

            collect(DISTINCT {
                source: alert.alertId,
                relationship: type(indicates),
                target: threat.name
            }) AS alert_threat_relationships
        """

        return self.neo4j.run_query(
            query,
            {
                "event_id": event_id
            }
        )

    # =========================================================
    # THREAT INVESTIGATION
    # =========================================================

    def retrieve_threat_investigation(
        self,
        threat_name: str
    ):

        query = """
        MATCH
            (threat:Threat)

        WHERE
            toLower(threat.name) =
            toLower($threat_name)

        OPTIONAL MATCH
            (alert:Alert)-[:INDICATES]->
            (threat)

        OPTIONAL MATCH
            (control:Control)-[:MITIGATES]->
            (threat)

        OPTIONAL MATCH
            (threat)-[:EXPLOITS]->
            (vulnerability:Vulnerability)

        OPTIONAL MATCH
            (procedure:ResponseProcedure)-[:SUPPORTS_RESPONSE_TO]->
            (threat)

        RETURN
            threat,

            collect(DISTINCT alert)
                AS alerts,

            collect(DISTINCT control)
                AS controls,

            collect(DISTINCT vulnerability)
                AS vulnerabilities,

            collect(DISTINCT procedure)
                AS procedures
        """

        return self.neo4j.run_query(
            query,
            {
                "threat_name": threat_name
            }
        )

    # =========================================================
    # THREAT TO ALERTS
    # =========================================================

    def retrieve_threat_alerts(
        self,
        threat_name: str
    ):

        query = """
        MATCH
            (alert:Alert)-[:INDICATES]->
            (threat:Threat)

        WHERE
            toLower(threat.name) =
            toLower($threat_name)

        OPTIONAL MATCH
            (event:Event)-[:CREATED_ALERT]->
            (alert)

        RETURN
            threat,

            collect(DISTINCT alert)
                AS alerts,

            collect(DISTINCT event)
                AS events,

            collect(DISTINCT {
                source: alert.alertId,
                relationship: "INDICATES",
                target: threat.name
            }) AS alert_threat_relationships,

            collect(DISTINCT {
                source: event.eventId,
                relationship: "CREATED_ALERT",
                target: alert.alertId
            }) AS event_alert_relationships
        """

        return self.neo4j.run_query(
            query,
            {
                "threat_name": threat_name
            }
        )

    # =========================================================
    # THREAT TO VULNERABILITIES
    # =========================================================

    def retrieve_threat_vulnerabilities(
        self,
        threat_name: str
    ):

        query = """
        MATCH
            (threat:Threat)-[:EXPLOITS]->
            (vulnerability:Vulnerability)

        WHERE
            toLower(threat.name) =
            toLower($threat_name)

        RETURN
            threat,

            collect(DISTINCT vulnerability)
                AS vulnerabilities,

            collect(DISTINCT {
                source: vulnerability.name,
                relationship: "RELATES_TO",
                target: threat.name
            }) AS vulnerability_threat_relationships
        """

        return self.neo4j.run_query(
            query,
            {
                "threat_name": threat_name
            }
        )

    # =========================================================
    # THREAT TO RESPONSES
    # =========================================================

    def retrieve_threat_response(
        self,
        threat_name: str
    ):

        query = """
        MATCH
            (threat:Threat)

        WHERE
            toLower(threat.name) =
            toLower($threat_name)

        OPTIONAL MATCH
            (procedure:ResponseProcedure)-[:SUPPORTS_RESPONSE_TO]->
            (threat)

        RETURN
            threat,

            collect(DISTINCT procedure)
                AS procedures
        """

        return self.neo4j.run_query(
            query,
            {
                "threat_name": threat_name
            }
        )

    # =========================================================
    # SERVICE INVESTIGATION
    # =========================================================

    def retrieve_service_investigation(
        self,
        service_name: str
    ):

        query = """
        MATCH
            (service:Service {name: $service_name})

        OPTIONAL MATCH
            (dependent:Service)-[:DEPENDS_ON]->
            (service)

        OPTIONAL MATCH
            (service)-[:DEPENDS_ON]->
            (dependency:Service)

        RETURN
            service,

            collect(DISTINCT dependent)
                AS dependents,

            collect(DISTINCT dependency)
                AS dependencies
        """

        return self.neo4j.run_query(
            query,
            {
                "service_name": service_name
            }
        )

    # =========================================================
    # DEVICE EVENTS
    # =========================================================

    def retrieve_device_events(
        self,
        device_id: str
    ):

        query = """
        MATCH
            (device:Device {deviceId: $device_id})

        OPTIONAL MATCH
            (device)-[:HAS_SECURITY_EVENT]->(event:Event)

        OPTIONAL MATCH
            (event)-[:CREATED_ALERT]->
            (alert:Alert)

        RETURN
            device,

            collect(DISTINCT event)
                AS events,

            collect(DISTINCT alert)
                AS alerts
        """

        return self.neo4j.run_query(
            query,
            {
                "device_id": device_id
            }
        )

    # =========================================================
    # DEVICE ALERTS
    # =========================================================

    def retrieve_device_alerts(
        self,
        device_id: str
    ):

        query = """
        MATCH
            (device:Device {deviceId: $device_id})

        OPTIONAL MATCH
            (event:Event)-[:AFFECTS]->
            (device)

        OPTIONAL MATCH
            (event)-[:CREATED_ALERT]->
            (alert:Alert)

        OPTIONAL MATCH
            (alert)-[:INDICATES]->
            (threat:Threat)

        RETURN
            device,

            collect(DISTINCT event)
                AS events,

            collect(DISTINCT alert)
                AS alerts,

            collect(DISTINCT threat)
                AS threats
        """

        return self.neo4j.run_query(
            query,
            {
                "device_id": device_id
            }
        )