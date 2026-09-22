package com.iotsecurity.soc.model.graph;

import org.springframework.data.neo4j.core.schema.Id;
import org.springframework.data.neo4j.core.schema.Node;

@Node("Threat")
public class Threat {

    @Id
    private String threatId;

    private String name;

    private String framework;

    public Threat() {
    }

    public Threat(
            String threatId,
            String name,
            String framework
    ) {
        this.threatId = threatId;
        this.name = name;
        this.framework = framework;
    }

    public String getThreatId() {
        return threatId;
    }

    public String getName() {
        return name;
    }

    public String getFramework() {
        return framework;
    }

    public void setThreatId(String threatId) {
        this.threatId = threatId;
    }

    public void setName(String name) {
        this.name = name;
    }

    public void setFramework(String framework) {
        this.framework = framework;
    }
}