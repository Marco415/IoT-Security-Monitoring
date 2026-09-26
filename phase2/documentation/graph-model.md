# Neo4j Security Knowledge Graph

## 1. Purpose

The Neo4j graph provides relationship-based security context for the SOC and RAG services.

The graph combines information from:

* Phase 1 microservices;
* Phase 2 SOC events;
* Phase 2 alerts;
* security knowledge;
* threats;
* vulnerabilities;
* controls;
* documentation.

---

# 2. Node Types

The graph contains the following primary node types:

```text
User
Role
Service
Endpoint
Asset
Event
Alert
Threat
Vulnerability
Control
Document
Procedure
```

---

# 3. Relationships

## Users and Roles

```text
(User)-[:HAS_ROLE]->(Role)
```

## Services and Endpoints

```text
(Service)-[:EXPOSES]->(Endpoint)
```

## Events and Services

```text
(Event)-[:OCCURRED_IN]->(Service)
```

## Events and Users

```text
(User)-[:GENERATED]->(Event)
```

## Alerts and Events

```text
(Alert)-[:TRIGGERED_BY]->(Event)
```

## Alerts and Threats

```text
(Alert)-[:INDICATES]->(Threat)
```

## Threats and Vulnerabilities

```text
(Threat)-[:EXPLOITS]->(Vulnerability)
```

## Vulnerabilities and Controls

```text
(Vulnerability)-[:MITIGATED_BY]->(Control)
```

## Documents and Controls

```text
(Document)-[:DESCRIBES]->(Control)
```

## Service Dependencies

```text
(Service)-[:DEPENDS_ON]->(Service)
```

---

# 4. Example

A failed-login investigation may produce:

```text
(User:admin)
      |
      | GENERATED
      v
(Event:FAILED_LOGIN)
      |
      | OCCURRED_IN
      v
(Service:auth-service)
      |
      ^
      |
(Alert:MULTIPLE_FAILED_LOGINS)
```

The alert can then be connected to security knowledge:

```text
Alert
  |
  | INDICATES
  v
Threat
  |
  | EXPLOITS
  v
Vulnerability
  |
  | MITIGATED_BY
  v
Control
  |
  | DESCRIBED_BY
  v
Document
```

This structure allows the RAG service to answer questions using both event evidence and security knowledge.

---

# 5. Required Graph Properties

Security entities should have stable identifiers.

Examples:

```text
User.username
Service.name
Event.eventId
Alert.alertId
Threat.name
Vulnerability.name
Control.controlId
Document.documentId
```

The graph ingestion process should use `MERGE` rather than creating duplicate nodes for the same entity.

---

# 6. Data Sources

## Phase 1

```text
auth-service
event-service
device-service
gateway
```

## Phase 2

```text
SOC events
SOC alerts
detection rules
service health
```

## Security Knowledge

```text
Threats
Vulnerabilities
Controls
Documents
Procedures
```
