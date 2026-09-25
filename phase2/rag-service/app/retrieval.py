from .neo4j_client import neo4j_client


QUERIES = {

    "alert_investigation": """
        MATCH (a:Alert)
        WHERE a.alertId = $identifier

        OPTIONAL MATCH (e:Event)-[:CREATED_ALERT]->(a)
        OPTIONAL MATCH (u:User)-[:TRIGGERED]->(e)
        OPTIONAL MATCH (a)-[:INDICATES]->(t:Threat)
        OPTIONAL MATCH (t)-[:TARGETS]->(s:Service)
        OPTIONAL MATCH (c:Control)-[:MITIGATES]->(t)
        OPTIONAL MATCH (p:Procedure)-[:SUPPORTS_RESPONSE_TO]->(t)

        RETURN
            a,
            collect(DISTINCT e) AS events,
            collect(DISTINCT u) AS users,
            collect(DISTINCT t) AS threats,
            collect(DISTINCT s) AS services,
            collect(DISTINCT c) AS controls,
            collect(DISTINCT p) AS procedures
    """,

    "threat_controls": """
        MATCH (t:Threat)
        OPTIONAL MATCH (c:Control)-[:MITIGATES]->(t)
        OPTIONAL MATCH (p:Procedure)-[:SUPPORTS_RESPONSE_TO]->(t)

        WHERE
            toLower(coalesce(t.name, '')) CONTAINS $searchText
            OR toLower(coalesce(t.threatId, '')) CONTAINS $searchText
            OR toLower(coalesce(t.description, '')) CONTAINS $searchText

        RETURN
            t AS threat,
            collect(DISTINCT c) AS controls,
            collect(DISTINCT p) AS procedures
    """,

    "service_dependencies": """
        MATCH (s:Service)
        OPTIONAL MATCH path=(s)-[:DEPENDS_ON*1..3]->(dependency:Service)

        WHERE
            toLower(coalesce(s.name, '')) CONTAINS $searchText

        RETURN
            s AS service,
            collect(DISTINCT dependency) AS dependencies
    """,

    "user_events": """
        MATCH (u:User)-[:TRIGGERED]->(e:Event)

        WHERE
            toLower(coalesce(u.username, '')) CONTAINS $searchText
            OR toLower(coalesce(u.userId, '')) CONTAINS $searchText

        OPTIONAL MATCH (e)-[:CREATED_ALERT]->(a:Alert)

        RETURN
            u AS user,
            collect(DISTINCT e) AS events,
            collect(DISTINCT a) AS alerts
    """,

    "service_information": """
        MATCH (s:Service)

        WHERE
            toLower(coalesce(s.name, '')) CONTAINS $searchText

        OPTIONAL MATCH (s)-[:EXPOSES]->(endpoint:Endpoint)
        OPTIONAL MATCH (s)-[:DEPENDS_ON]->(dependency:Service)
        OPTIONAL MATCH (t:Threat)-[:TARGETS]->(s)

        RETURN
            s AS service,
            collect(DISTINCT endpoint) AS endpoints,
            collect(DISTINCT dependency) AS dependencies,
            collect(DISTINCT t) AS threats
    """,

    "security_overview": """
        MATCH (a:Alert)
        OPTIONAL MATCH (a)-[:INDICATES]->(t:Threat)
        OPTIONAL MATCH (c:Control)-[:MITIGATES]->(t)

        RETURN
            collect(DISTINCT a) AS alerts,
            collect(DISTINCT t) AS threats,
            collect(DISTINCT c) AS controls
        LIMIT 1
    """
}


def extract_identifier(question: str) -> str:

    words = question.replace("?", " ").split()

    for word in words:

        cleaned = word.strip(".,!?():[]{}")

        if (
            cleaned.startswith("alert-")
            or cleaned.startswith("evt-")
            or cleaned.startswith("user-")
            or cleaned.startswith("service-")
        ):
            return cleaned

    return ""


def extract_search_text(question: str) -> str:

    identifier = extract_identifier(question)

    if identifier:
        return identifier.lower()

    question = question.lower()

    stop_words = {
        "what",
        "which",
        "who",
        "why",
        "was",
        "were",
        "is",
        "are",
        "the",
        "this",
        "that",
        "can",
        "could",
        "should",
        "how",
        "do",
        "does",
        "and",
        "for",
        "from",
        "with",
        "about",
        "please",
        "show",
        "find",
        "tell",
        "me",
        "this",
        "threat",
        "controls",
        "control",
        "service",
        "services",
    }

    words = [
        word.strip(".,!?():[]{}")
        for word in question.split()
    ]

    meaningful = [
        word
        for word in words
        if word and word not in stop_words
    ]

    return " ".join(meaningful)


def retrieve(
    intent: str,
    question: str
) -> list[dict]:

    query = QUERIES[intent]

    identifier = extract_identifier(question)

    search_text = extract_search_text(question)

    return neo4j_client.execute_query(
        query,
        {
            "identifier": identifier,
            "searchText": search_text
        }
    )