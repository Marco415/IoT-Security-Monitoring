MATCH (s:Service {name: 'api-gateway'})
      <-[:AFFECTS]-(a:Alert)
RETURN
    a.id AS alertId,
    a.ruleName AS ruleName,
    a.severity AS severity,
    a.status AS status,
    a.timestamp AS timestamp,
    a.message AS message
ORDER BY a.timestamp DESC;



MATCH (u:User)
      -[:TRIGGERED]->(e:Event)
      -[:CREATED_ALERT]->(a:Alert)
WHERE a.severity = 'HIGH'
RETURN DISTINCT
    u.userId AS userId,
    u.username AS username,
    a.id AS alertId,
    a.ruleName AS ruleName,
    a.severity AS severity,
    a.timestamp AS timestamp
ORDER BY a.timestamp DESC;



MATCH (s:Service {name: 'api-gateway'})
      <-[:AFFECTS]-(a:Alert)
      -[:INDICATES]->(t:Threat)
RETURN DISTINCT
    s.name AS service,
    t.id AS threatId,
    t.name AS threat,
    a.id AS alertId,
    a.ruleName AS ruleName
ORDER BY t.name;



MATCH (a:Alert {alertId: 'alert-001'})
      -[:INDICATES]->(t:Threat)
      <-[:MITIGATES]-(c:Control)
RETURN DISTINCT
    a.alertId AS alertId,
    a.ruleName AS ruleName,
    t.id AS threatId,
    t.name AS threat,
    c.id AS controlId,
    c.name AS control
ORDER BY c.name;



MATCH path = (s:Service {name: 'soc-service'})
             -[:DEPENDS_ON*1..3]->(dependent:Service)
RETURN
    s.name AS sourceService,
    dependent.name AS affectedService,
    length(path) AS dependencyDepth,
    [node IN nodes(path) | node.name] AS dependencyPath
ORDER BY dependencyDepth;



MATCH (a:Alert)
      -[:INDICATES]->(t:Threat {name: "Brute Force"})
RETURN
    t.id AS threatId,
    t.name AS threat,
    a.alertId AS alertId,
    a.ruleName AS ruleName,
    a.severity AS severity,
    a.status AS status,
    a.timestamp AS timestamp
ORDER BY a.timestamp DESC;