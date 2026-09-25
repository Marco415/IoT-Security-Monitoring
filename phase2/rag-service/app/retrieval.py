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