from neo4j import GraphDatabase

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

    def close(self):
        self.driver.close()

    def verify_connection(self):
        with self.driver.session(
            database=NEO4J_DATABASE
        ) as session:

            result = session.run(
                "RETURN 1 AS value"
            )

            record = result.single()

            return record["value"] == 1

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
                record.data()
                for record in result
            ]