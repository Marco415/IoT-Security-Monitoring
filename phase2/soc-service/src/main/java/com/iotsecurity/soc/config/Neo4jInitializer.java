package com.iotsecurity.soc.config;

import com.iotsecurity.soc.service.Neo4jGraphService;
import org.springframework.boot.CommandLineRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class Neo4jInitializer {

    @Bean
    public CommandLineRunner initializeNeo4j(
            Neo4jGraphService neo4jGraphService
    ) {

        return args -> {

            neo4jGraphService.initializeGraph();
        };
    }
}