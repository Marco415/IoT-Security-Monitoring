package com.iotsecurity.soc.model.graph;

import org.springframework.data.neo4j.core.schema.Id;
import org.springframework.data.neo4j.core.schema.Node;

@Node("Document")
public class Document {

    @Id
    private String documentId;

    private String name;

    private String type;

    public Document() {
    }

    public Document(
            String documentId,
            String name,
            String type
    ) {
        this.documentId = documentId;
        this.name = name;
        this.type = type;
    }

    public String getDocumentId() {
        return documentId;
    }

    public String getName() {
        return name;
    }

    public String getType() {
        return type;
    }
}