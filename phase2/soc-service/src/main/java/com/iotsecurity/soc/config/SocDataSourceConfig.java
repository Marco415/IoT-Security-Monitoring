package com.iotsecurity.soc.config;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.jdbc.autoconfigure.DataSourceProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Primary;

import javax.sql.DataSource;

@Configuration
public class SocDataSourceConfig {

    @Bean
    @Primary
    @ConfigurationProperties("spring.datasource")
    public DataSourceProperties socDataSourceProperties() {
        return new DataSourceProperties();
    }

    @Bean(name = "socDataSource")
    @Primary
    public DataSource socDataSource() {
        return socDataSourceProperties()
                .initializeDataSourceBuilder()
                .build();
    }
}