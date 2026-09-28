package com.iotsecurity.soc.config;

import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.datasource.DriverManagerDataSource;

import javax.sql.DataSource;

@Configuration
public class SourceDatabaseConfig {

    /*
     * ============================================================
     * DEVICE DATABASE
     * ============================================================
     */

    @Bean(name = "deviceDataSource")
    public DataSource deviceDataSource(
            @Value("${soc.source-databases.device.url}") String url,
            @Value("${soc.source-databases.device.username}") String username,
            @Value("${soc.source-databases.device.password}") String password) {

        DriverManagerDataSource dataSource = new DriverManagerDataSource();

        dataSource.setDriverClassName("org.postgresql.Driver");
        dataSource.setUrl(url);
        dataSource.setUsername(username);
        dataSource.setPassword(password);

        return dataSource;
    }

    @Bean(name = "deviceJdbcTemplate")
    public JdbcTemplate deviceJdbcTemplate(
            @Qualifier("deviceDataSource") DataSource dataSource) {

        return new JdbcTemplate(dataSource);
    }


    /*
     * ============================================================
     * AUTH DATABASE
     * ============================================================
     */

    @Bean(name = "authSourceDataSource")
    public DataSource authSourceDataSource(
            @Value("${soc.source-databases.auth.url}") String url,
            @Value("${soc.source-databases.auth.username}") String username,
            @Value("${soc.source-databases.auth.password}") String password) {

        DriverManagerDataSource dataSource = new DriverManagerDataSource();

        dataSource.setDriverClassName("org.postgresql.Driver");
        dataSource.setUrl(url);
        dataSource.setUsername(username);
        dataSource.setPassword(password);

        return dataSource;
    }

    @Bean(name = "authSourceJdbcTemplate")
    public JdbcTemplate authSourceJdbcTemplate(
            @Qualifier("authSourceDataSource") DataSource dataSource) {

        return new JdbcTemplate(dataSource);
    }
}