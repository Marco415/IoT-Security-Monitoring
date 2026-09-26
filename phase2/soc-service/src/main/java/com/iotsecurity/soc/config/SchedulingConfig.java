package com.iotsecurity.soc.config;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.annotation.Configuration;
import org.springframework.scheduling.annotation.EnableScheduling;
import org.springframework.scheduling.annotation.Scheduled;

@Configuration
@EnableScheduling
public class SchedulingConfig {

    private static final Logger log =
            LoggerFactory.getLogger(SchedulingConfig.class);

    @Scheduled(fixedRate = 10000)
    public void schedulerHeartbeat() {
        log.info("SOC scheduler heartbeat");
    }
}