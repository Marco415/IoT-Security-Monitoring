package com.iotsecurity.event.config;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.slf4j.MDC;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.UUID;

@Component
public class CorrelationIdFilter
        extends OncePerRequestFilter {

    private static final Logger log =
            LoggerFactory.getLogger(
                    CorrelationIdFilter.class
            );

    public static final String CORRELATION_ID =
            "X-Correlation-ID";

    @Override
    protected void doFilterInternal(
            HttpServletRequest request,
            HttpServletResponse response,
            FilterChain filterChain)
            throws ServletException, IOException {

        String correlationId =
                request.getHeader(CORRELATION_ID);

        if (correlationId == null
                || correlationId.isBlank()) {

            correlationId =
                    UUID.randomUUID().toString();
        }

        try {

            MDC.put(
                    CORRELATION_ID,
                    correlationId
            );

            response.setHeader(
                    CORRELATION_ID,
                    correlationId
            );

            log.debug(
                    "Processing event service request method={} path={} correlationId={}",
                    request.getMethod(),
                    request.getRequestURI(),
                    correlationId
            );

            filterChain.doFilter(
                    request,
                    response
            );

        } catch (Exception exception) {

            log.error(
                    "Event service request failed path={} correlationId={}",
                    request.getRequestURI(),
                    correlationId,
                    exception
            );

            throw exception;

        } finally {

            MDC.remove(CORRELATION_ID);
        }
    }
}