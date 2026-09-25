from neo4j import GraphDatabase

from .config import settings


class Neo4jClient:

    def __init__(self):
        self.driver = GraphDatabase.driver(
            settings.neo4j_uri,
            auth=(
                settings.neo4j_username,
                settings.neo4j_password
            )
        )

    def verify_connection(self) -> bool:
        try:
            self.driver.verify_connectivity()
            return True
        except Exception:
            return False

    def close(self):
        self.driver.close()

    def execute_query(
        self,
        query: str,
        parameters: dict | None = None
    ) -> list[dict]:

        with self.driver.session(
            database=settings.neo4j_database
        ) as session:

            result = session.run(
                query,
                parameters or {}
            )

            return [
                record.data()
                for record in result
            ]


neo4j_client = Neo4jClient()