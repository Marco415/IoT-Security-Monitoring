from neo4j import GraphDatabase
from neo4j.graph import Node, Relationship, Path

from app.config import (
    NEO4J_URI,
    NEO4J_USERNAME,
    NEO4J_PASSWORD,
    NEO4J_DATABASE,
)


class Neo4jClient:

    def __init__(self):
        self.driver = GraphDatabase.driver(
            NEO4J_URI,
            auth=(
                NEO4J_USERNAME,
                NEO4J_PASSWORD
            )
        )

    # =========================================================
    # CLOSE
    # =========================================================

    def close(self):
        self.driver.close()

    # =========================================================
    # CONNECTION TEST
    # =========================================================

    def verify_connection(self):

        with self.driver.session(
            database=NEO4J_DATABASE
        ) as session:

            result = session.run(
                "RETURN 1 AS value"
            )

            record = result.single()

            return record["value"] == 1

    # =========================================================
    # NEO4J VALUE NORMALIZATION
    # =========================================================

    def _normalize_value(self, value):

        # -----------------------------------------------------
        # Neo4j Node
        # -----------------------------------------------------

        if isinstance(value, Node):

            return {
                "id": self._get_business_id(
                    value
                ),
                "labels": list(
                    value.labels
                ),
                "properties": dict(
                    value
                ),
            }

        # -----------------------------------------------------
        # Neo4j Relationship
        # -----------------------------------------------------

        if isinstance(value, Relationship):

            return {
                "id": str(
                    value.id
                ),
                "relationship": value.type,
                "properties": dict(
                    value
                ),
            }

        # -----------------------------------------------------
        # Neo4j Path
        # -----------------------------------------------------

        if isinstance(value, Path):

            return {
                "nodes": [
                    self._normalize_value(node)
                    for node in value.nodes
                ],
                "relationships": [
                    self._normalize_value(
                        relationship
                    )
                    for relationship in value.relationships
                ],
            }

        # -----------------------------------------------------
        # Dictionary
        # -----------------------------------------------------

        if isinstance(value, dict):

            return {
                key: self._normalize_value(
                    item
                )
                for key, item in value.items()
            }

        # -----------------------------------------------------
        # List / Tuple
        # -----------------------------------------------------

        if isinstance(
            value,
            (list, tuple)
        ):

            return [
                self._normalize_value(item)
                for item in value
            ]

        # -----------------------------------------------------
        # Primitive value
        # -----------------------------------------------------

        return value

    # =========================================================
    # BUSINESS ID
    # =========================================================

    def _get_business_id(
        self,
        node: Node
    ):

        properties = dict(
            node
        )

        # Prefer stable application-level IDs.
        for property_name in [
            "alertId",
            "eventId",
            "userId",
            "deviceId",
            "serviceId",
            "controlId",
            "threatId",
            "ruleId",
            "procedureId",
            "vulnerabilityId",
            "name",
        ]:

            value = properties.get(
                property_name
            )

            if value is not None:
                return str(value)

        # Fall back to Neo4j's internal ID.
        return str(
            node.id
        )

    # =========================================================
    # RUN QUERY
    # =========================================================

    def run_query(
        self,
        query: str,
        parameters: dict | None = None
    ):

        with self.driver.session(
            database=NEO4J_DATABASE
        ) as session:

            result = session.run(
                query,
                parameters or {}
            )

            return [
                self._normalize_value(
                    record.data()
                )
                for record in result
            ]