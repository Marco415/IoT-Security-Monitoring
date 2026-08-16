package com.iotsecurity.gateway;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilter;
import org.springframework.web.server.WebFilterChain;
import reactor.core.publisher.Mono;

import java.util.UUID;

@Component
@Order(Ordered.HIGHEST_PRECEDENCE)
public class CorrelationIdFilter implements WebFilter {

    private static final Logger log =
            LoggerFactory.getLogger(CorrelationIdFilter.class);

    public static final String CORRELATION_ID =
            "X-Correlation-ID";

    @Override
    public Mono<Void> filter(
            ServerWebExchange exchange,
            WebFilterChain chain) {

        String correlationId =
                exchange.getRequest()
                        .getHeaders()
                        .getFirst(CORRELATION_ID);

        if (correlationId == null
                || correlationId.isBlank()) {

            correlationId =
                    UUID.randomUUID().toString();

            log.debug(
                    "Generated new correlation ID correlationId={}",
                    correlationId
            );

        } else {

            log.debug(
                    "Received correlation ID correlationId={}",
                    correlationId
            );
        }

        ServerWebExchange modifiedExchange =
                exchange.mutate()
                        .request(
                                exchange.getRequest()
                                        .mutate()
                                        .header(
                                                CORRELATION_ID,
                                                correlationId
                                        )
                                        .build()
                        )
                        .build();

        final String finalCorrelationId =
                correlationId;

        return chain.filter(modifiedExchange)
                .doOnSuccess(
                        unused -> log.debug(
                                "Gateway request completed method={} path={} correlationId={}",
                                exchange.getRequest().getMethod(),
                                exchange.getRequest().getPath(),
                                finalCorrelationId
                        )
                )
                .doOnError(
                        exception -> log.error(
                                "Gateway request failed method={} path={} correlationId={}",
                                exchange.getRequest().getMethod(),
                                exchange.getRequest().getPath(),
                                finalCorrelationId,
                                exception
                        )
                )
                .contextWrite(
                        context -> context.put(
                                CORRELATION_ID,
                                finalCorrelationId
                        )
                );
    }
}