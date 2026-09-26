# SOC Detection Rules

## 1. Purpose

The SOC detection engine analyses normalized security events collected from the IoT Security Monitoring microservices.

The detection engine currently implements three security detection rules:

1. `MULTIPLE_FAILED_LOGINS`
2. `UNAUTHORIZED_ENDPOINT_ACCESS`
3. `SERVICE_FAILURE`

Each detection rule receives normalized SOC events and may generate a SOC alert.

---

# 2. Rule: MULTIPLE_FAILED_LOGINS

## Rule Name

`MULTIPLE_FAILED_LOGINS`

## Purpose

Detect repeated authentication failures that may indicate password guessing, credential abuse, or another abnormal authentication pattern.

## Input Events

Primary source:

```text
auth_events
```

Normalized event type:

```text
FAILED_LOGIN
```

Relevant fields include:

```text
eventId
timestamp
serviceName
eventType
userId
sourceIp
message
correlationId
```

## Detection Condition

The rule is triggered when:

```text
5 or more FAILED_LOGIN events
```

are associated with the same user or source IP during:

```text
5 minutes
```

The implementation should group events by the relevant authentication identity and/or source IP.

## Severity

```text
HIGH
```

## Generated Alert

```text
Detection Rule:
MULTIPLE_FAILED_LOGINS

Severity:
HIGH

Status:
OPEN
```

The generated alert should retain references to the events that caused the detection.

## Recommended Response

The SOC operator should investigate:

* the affected account;
* the originating IP address;
* the authentication timestamps;
* the number of failed attempts;
* whether a successful login followed the failed attempts;
* whether the source IP is associated with another security event.

---

# 3. Rule: UNAUTHORIZED_ENDPOINT_ACCESS

## Rule Name

`UNAUTHORIZED_ENDPOINT_ACCESS`

## Purpose

Detect repeated attempts to access protected API resources without sufficient authorization.

## Input Events

Primary sources:

```text
Gateway events
Security events
```

Relevant HTTP status codes:

```text
401
403
```

Where:

```text
401 = Unauthorized
403 = Forbidden
```

Relevant normalized fields include:

```text
timestamp
serviceName
sourceIp
userId
endpoint
httpMethod
statusCode
correlationId
```

## Detection Condition

The rule is triggered when repeated:

```text
401
```

or:

```text
403
```

responses are associated with the same user or source IP during a defined detection window.

The implementation should retain the source IP, endpoint and correlation information so that the SOC operator can investigate the access pattern.

## Severity

The implementation may assign:

```text
MEDIUM
```

for repeated unauthorized requests.

A higher severity may be assigned when the event pattern is associated with additional security indicators.

## Generated Alert

```text
Detection Rule:
UNAUTHORIZED_ENDPOINT_ACCESS

Severity:
MEDIUM

Status:
OPEN
```

## Recommended Response

The SOC operator should investigate:

* source IP;
* requested endpoint;
* HTTP method;
* user identity;
* number of unauthorized requests;
* affected service;
* correlation IDs;
* related authentication events.

---

# 4. Rule: SERVICE_FAILURE

## Rule Name

`SERVICE_FAILURE`

## Purpose

Detect repeated service failures that may indicate an application failure, infrastructure problem, dependency failure, or security-related disruption.

## Input Events

Primary sources:

```text
Gateway logs
Actuator health events
SOC health collectors
```

Relevant indicators include:

```text
HTTP 500 responses
Failed health checks
Service unavailable responses
Repeated downstream failures
```

## Detection Condition

The rule is triggered when a service produces repeated failures during the configured detection window.

Examples include:

```text
Multiple HTTP 500 responses
```

or:

```text
Repeated failed health checks
```

The implementation should associate the failure with:

```text
serviceName
endpoint
timestamp
statusCode
correlationId
```

where available.

## Severity

```text
HIGH
```

## Generated Alert

```text
Detection Rule:
SERVICE_FAILURE

Severity:
HIGH

Status:
OPEN
```

## Recommended Response

The SOC operator should investigate:

* service health;
* recent deployments;
* dependency availability;
* database connectivity;
* gateway failures;
* application logs;
* related security events;
* correlation IDs associated with the failure.

---

# 5. Alert Lifecycle

Generated alerts use the following lifecycle:

```text
OPEN
  │
  ▼
INVESTIGATING
  │
  ▼
RESOLVED
  │
  ▼
CLOSED
```

An alert should initially be created with:

```text
status = OPEN
```

unless an explicit status is supplied by the system.

---

# 6. Alert Traceability

Every generated alert should retain enough information to trace the alert back to its source events.

Recommended fields include:

```text
alertId
detectionRule
severity
status
timestamp
serviceName
userId
sourceIp
sourceEventId
correlationId
```

This traceability allows the SOC dashboard, Neo4j knowledge graph and RAG service to connect alerts with their originating events.

---

# 7. Detection Summary

| Rule                           | Input                   | Condition                                                  | Severity |
| ------------------------------ | ----------------------- | ---------------------------------------------------------- | -------- |
| `MULTIPLE_FAILED_LOGINS`       | Authentication events   | ≥5 failed logins for same identity/source during 5 minutes | HIGH     |
| `UNAUTHORIZED_ENDPOINT_ACCESS` | Gateway/security events | Repeated 401/403 requests from same identity/source        | MEDIUM   |
| `SERVICE_FAILURE`              | Gateway/health events   | Repeated 500 responses or failed health checks             | HIGH     |

---

# 8. Demonstration Data

A demonstration of the SOC should be capable of producing at least:

### Authentication example

```text
admin
172.18.0.14
FAILED_LOGIN
FAILED_LOGIN
FAILED_LOGIN
FAILED_LOGIN
FAILED_LOGIN
```

which produces:

```text
MULTIPLE_FAILED_LOGINS
HIGH
OPEN
```

### Unauthorized access example

```text
401
401
403
401
```

from the same source produces:

```text
UNAUTHORIZED_ENDPOINT_ACCESS
MEDIUM
OPEN
```

### Service failure example

```text
device-service
500
500
500
```

or repeated failed health checks produces:

```text
SERVICE_FAILURE
HIGH
OPEN
```
