// ============================================================
// SECURITY KNOWLEDGE SEED
// IoT Security Monitoring SOC
//
// Sources:
//   MITRE ATT&CK
//   CWE
//   OWASP API Security
//
// This file contains REFERENCE KNOWLEDGE.
// It does not prove that any vulnerability exists in the system.
// ============================================================


// ============================================================
// 1. PASSWORD SPRAYING
// MITRE ATT&CK T1110.003
// CWE-307
// ============================================================

MERGE (t:Threat {id: 'T-PS-001'})
SET t.name = 'Password Spraying',
    t.referenceId = 'T1110.003',
    t.source = 'MITRE ATT&CK',
    t.sourceUrl = 'https://attack.mitre.org/techniques/T1110/003/',
    t.description =
        'An attack pattern in which one or a small number of commonly used passwords are attempted against multiple user accounts.',
    t.status = 'reference',
    t.lastReviewed = '2026-09-28';


MERGE (v:Vulnerability {id: 'CWE-307'})
SET v.name = 'Improper Restriction of Excessive Authentication Attempts',
    v.referenceId = 'CWE-307',
    v.source = 'CWE',
    v.sourceUrl = 'https://cwe.mitre.org/data/definitions/307.html',
    v.description =
        'A weakness in which the application does not sufficiently restrict repeated failed authentication attempts.',
    v.status = 'reference weakness type',
    v.lastReviewed = '2026-09-28';


MERGE (c:Control {id: 'C-AUTH-001'})
SET c.name = 'Login Throttling and MFA',
    c.description =
        'Limit repeated authentication attempts and require an additional authentication factor for protected accounts.',
    c.status = 'reference control',
    c.lastReviewed = '2026-09-28';


MERGE (p:Procedure {id: 'P-AUTH-001'})
SET p.title = 'Investigate Suspected Password Spraying',
    p.revision = 1,
    p.text =
        'Check the number of distinct accounts targeted, source IP addresses, authentication timestamps, failed and successful logins, and whether the activity was an approved security test. Determine whether the observed pattern is consistent with password spraying before classifying the activity.',
    p.status = 'reviewed',
    p.lastReviewed = '2026-09-28';


// Relationships

MATCH (t:Threat {id: 'T-PS-001'})
MATCH (v:Vulnerability {id: 'CWE-307'})
MERGE (t)-[:EXPLOITS]->(v);

MATCH (c:Control {id: 'C-AUTH-001'})
MATCH (t:Threat {id: 'T-PS-001'})
MERGE (c)-[:MITIGATES]->(t);

MATCH (p:Procedure {id: 'P-AUTH-001'})
MATCH (t:Threat {id: 'T-PS-001'})
MERGE (p)-[:SUPPORTS_RESPONSE_TO]->(t);


// ============================================================
// 2. BROKEN OBJECT LEVEL AUTHORIZATION
// OWASP API1:2023
// CWE-639
// ============================================================

MERGE (t:Threat {id: 'T-BOLA-001'})
SET t.name = 'Broken Object Level Authorization',
    t.referenceId = 'API1:2023',
    t.source = 'OWASP API Security',
    t.sourceUrl = 'https://api-security.owasp.org/editions/2023/en/0xa1-broken-object-level-authorization/',
    t.description =
        'An API access-control problem in which a user can manipulate an object identifier and potentially access an object belonging to another user.',
    t.status = 'reference',
    t.lastReviewed = '2026-09-28';


MERGE (v:Vulnerability {id: 'CWE-639'})
SET v.name = 'Authorization Bypass Through User-Controlled Key',
    v.referenceId = 'CWE-639',
    v.source = 'CWE',
    v.sourceUrl = 'https://cwe.mitre.org/data/definitions/639.html',
    v.description =
        'A weakness where authorization does not adequately prevent a user from accessing another users data by modifying a user-controlled key identifying the requested record.',
    v.status = 'reference weakness type',
    v.lastReviewed = '2026-09-28';


MERGE (c:Control {id: 'C-API-001'})
SET c.name = 'Per-Object Authorization Checks',
    c.description =
        'Verify on every object access that the authenticated user has permission to access the specific requested object.',
    c.status = 'reference control',
    c.lastReviewed = '2026-09-28';


MERGE (p:Procedure {id: 'P-API-001'})
SET p.title = 'Investigate Suspected Object Access Abuse',
    p.revision = 1,
    p.text =
        'Identify the authenticated user, requested object identifiers, endpoint, HTTP method, response status, and sequence of object IDs. Determine whether the requested objects belong to the requesting user. Check whether the activity was an approved security test before classifying it as a vulnerability.',
    p.status = 'reviewed',
    p.lastReviewed = '2026-09-28';


// Relationships

MATCH (t:Threat {id: 'T-BOLA-001'})
MATCH (v:Vulnerability {id: 'CWE-639'})
MERGE (t)-[:EXPLOITS]->(v);

MATCH (c:Control {id: 'C-API-001'})
MATCH (t:Threat {id: 'T-BOLA-001'})
MERGE (c)-[:MITIGATES]->(t);

MATCH (p:Procedure {id: 'P-API-001'})
MATCH (t:Threat {id: 'T-BOLA-001'})
MERGE (p)-[:SUPPORTS_RESPONSE_TO]->(t);


// ============================================================
// 3. UNRESTRICTED RESOURCE CONSUMPTION
// OWASP API4:2023
// CWE-770
// ============================================================

MERGE (t:Threat {id: 'T-RESOURCE-001'})
SET t.name = 'Unrestricted Resource Consumption',
    t.referenceId = 'API4:2023',
    t.source = 'OWASP API Security',
    t.sourceUrl = 'https://api-security.owasp.org/editions/2023/en/0xa4-unrestricted-resource-consumption/',
    t.description =
        'An API abuse pattern involving excessive requests or resource-intensive operations that consume disproportionate system resources and may reduce service availability.',
    t.status = 'reference',
    t.lastReviewed = '2026-09-28';


MERGE (v:Vulnerability {id: 'CWE-770'})
SET v.name = 'Allocation of Resources Without Limits or Throttling',
    v.referenceId = 'CWE-770',
    v.source = 'CWE',
    v.sourceUrl = 'https://cwe.mitre.org/data/definitions/770.html',
    v.description =
        'A weakness where resources are allocated without adequate limits, quotas or throttling, allowing excessive consumption that may affect system availability.',
    v.status = 'reference weakness type',
    v.lastReviewed = '2026-09-28';


MERGE (c:Control {id: 'C-API-002'})
SET c.name = 'Request Limits and Resource Quotas',
    c.description =
        'Apply request-rate limits, quotas and resource controls to expensive API operations and monitor their resource consumption.',
    c.status = 'reference control',
    c.lastReviewed = '2026-09-28';


MERGE (p:Procedure {id: 'P-API-002'})
SET p.title = 'Investigate Suspected Resource Exhaustion',
    p.revision = 1,
    p.text =
        'Check request volume, source IPs, endpoint, request parameters, response latency, error rates and service health. Determine whether expensive operations were invoked excessively and whether the activity was legitimate or an approved test.',
    p.status = 'reviewed',
    p.lastReviewed = '2026-09-28';


// Relationships

MATCH (t:Threat {id: 'T-RESOURCE-001'})
MATCH (v:Vulnerability {id: 'CWE-770'})
MERGE (t)-[:EXPLOITS]->(v);

MATCH (c:Control {id: 'C-API-002'})
MATCH (t:Threat {id: 'T-RESOURCE-001'})
MERGE (c)-[:MITIGATES]->(t);

MATCH (p:Procedure {id: 'P-API-002'})
MATCH (t:Threat {id: 'T-RESOURCE-001'})
MERGE (p)-[:SUPPORTS_RESPONSE_TO]->(t);


// ============================================================
// 4. OPTIONAL: SECURITY KNOWLEDGE CATEGORY
// ============================================================

MERGE (auth:SecurityCategory {id: 'CAT-AUTH'})
SET auth.name = 'Authentication Security';

MERGE (api:SecurityCategory {id: 'CAT-API'})
SET api.name = 'API Security';

MERGE (availability:SecurityCategory {id: 'CAT-AVAILABILITY'})
SET availability.name = 'Availability Security';


MATCH (t:Threat {id: 'T-PS-001'})
MATCH (c:SecurityCategory {id: 'CAT-AUTH'})
MERGE (t)-[:BELONGS_TO]->(c);

MATCH (t:Threat {id: 'T-BOLA-001'})
MATCH (c:SecurityCategory {id: 'CAT-API'})
MERGE (t)-[:BELONGS_TO]->(c);

MATCH (t:Threat {id: 'T-RESOURCE-001'})
MATCH (c:SecurityCategory {id: 'CAT-AVAILABILITY'})
MERGE (t)-[:BELONGS_TO]->(c);