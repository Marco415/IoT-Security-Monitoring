package com.iotsecurity.soc.model.graph;

import org.springframework.data.neo4j.core.schema.Id;
import org.springframework.data.neo4j.core.schema.Node;

@Node("Control")
public class Control {

    @Id
    private String controlId;

    private String name;

    public Control() {
    }

    public Control(
            String controlId,
            String name
    ) {
        this.controlId = controlId;
        this.name = name;
    }

    public String getControlId() {
        return controlId;
    }

    public String getName() {
        return name;
    }

    public void setControlId(String controlId) {
        this.controlId = controlId;
    }

    public void setName(String name) {
        this.name = name;
    }
}