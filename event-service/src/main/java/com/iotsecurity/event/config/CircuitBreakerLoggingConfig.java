package com.iotsecurity.event.config;

import io.github.resilience4j.circuitbreaker.CircuitBreaker;
import io.github.resilience4j.circuitbreaker.CircuitBreakerRegistry;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.annotation.Configuration;

@Configuration
public class CircuitBreakerLoggingConfig {

    private static final Logger log =
            LoggerFactory.getLogger(CircuitBreakerLoggingConfig.class);

    public CircuitBreakerLoggingConfig(
            CircuitBreakerRegistry circuitBreakerRegistry) {

        CircuitBreaker circuitBreaker =
                circuitBreakerRegistry.circuitBreaker(
                        "deviceServiceCircuitBreaker"
                );

        circuitBreaker
                .getEventPublisher()
                .onStateTransition(event ->
                        log.warn(
                                "CIRCUIT BREAKER STATE CHANGE: name={} from={} to={}",
                                event.getCircuitBreakerName(),
                                event.getStateTransition()
                                        .getFromState(),
                                event.getStateTransition()
                                        .getToState()
                        )
                );

        circuitBreaker
                .getEventPublisher()
                .onError(event ->
                        log.warn(
                                "CIRCUIT BREAKER ERROR: name={} duration={}ms",
                                event.getCircuitBreakerName(),
                                event.getElapsedDuration().toMillis()
                        )
                );

        circuitBreaker
                .getEventPublisher()
                .onSuccess(event ->
                        log.info(
                                "CIRCUIT BREAKER SUCCESS: name={} duration={}ms",
                                event.getCircuitBreakerName(),
                                event.getElapsedDuration().toMillis()
                        )
                );
    }
}