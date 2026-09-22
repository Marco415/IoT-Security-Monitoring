package com.iotsecurity.soc.repository;

import com.iotsecurity.soc.model.graph.Threat;

import org.springframework.data.neo4j.repository.Neo4jRepository;

public interface ThreatRepository
        extends Neo4jRepository<Threat, String> {

}