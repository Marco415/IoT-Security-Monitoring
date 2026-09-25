import json
from typing import Any


def neo4j_value(value: Any) -> Any:

    if value is None:
        return None

    if hasattr(value, "items"):
        return {
            key: neo4j_value(val)
            for key, val in value.items()
        }

    if isinstance(value, list):
        return [
            neo4j_value(item)
            for item in value
        ]

    return value


def build_evidence(results: list[dict]) -> dict:

    nodes = []
    relationships = []

    seen_nodes = set()
    seen_relationships = set()

    def add_node(label: str, properties: dict):

        identity = (
            label,
            properties.get("alertId")
            or properties.get("eventId")
            or properties.get("userId")
            or properties.get("threatId")
            or properties.get("name")
        )

        if identity in seen_nodes:
            return

        seen_nodes.add(identity)

        nodes.append({
            "label": label,
            "properties": properties
        })

    for result in results:

        for key, value in result.items():

            value = neo4j_value(value)

            if isinstance(value, dict):

                labels = value.get("labels", [])

                if labels:

                    label = labels[0]

                    properties = value.get(
                        "properties",
                        {}
                    )

                    add_node(
                        label,
                        properties
                    )

            elif isinstance(value, list):

                for item in value:

                    if not isinstance(item, dict):
                        continue

                    labels = item.get("labels", [])

                    if labels:

                        add_node(
                            labels[0],
                            item.get(
                                "properties",
                                {}
                            )
                        )

    return {
        "nodes": nodes,
        "relationships": relationships
    }


def evidence_to_text(evidence: dict) -> str:

    lines = []

    lines.append("RETRIEVED GRAPH NODES:")

    for node in evidence["nodes"]:

        lines.append(
            f"- {node['label']}: "
            f"{json.dumps(node['properties'], default=str)}"
        )

    lines.append("")
    lines.append("RETRIEVED GRAPH RELATIONSHIPS:")

    if evidence["relationships"]:

        for relationship in evidence["relationships"]:

            lines.append(
                f"- {relationship['source']} "
                f"-[{relationship['relationship']}]-> "
                f"{relationship['target']}"
            )

    else:

        lines.append(
            "- Relationships are represented by "
            "the Cypher traversal used to retrieve the nodes."
        )

    return "\n".join(lines)


def build_prompt(
    question: str,
    evidence_text: str
) -> str:

    return f"""
You are a security operations assistant.

Answer the user's question using ONLY the supplied
knowledge graph evidence.

Do not invent:
- users
- events
- alerts
- threats
- controls
- services
- procedures
- timestamps
- relationships
- security conclusions

If the evidence does not contain enough information,
say:

"The knowledge graph does not contain enough information
to answer this question."

Explain the answer clearly and concisely.

When discussing recommended controls or procedures,
only mention controls or procedures explicitly present
in the evidence.

User question:
{question}

Graph evidence:
{evidence_text}

Answer:
""".strip()