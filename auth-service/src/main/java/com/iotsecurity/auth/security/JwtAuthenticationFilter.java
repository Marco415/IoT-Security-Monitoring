package com.iotsecurity.auth.security;

import com.iotsecurity.auth.entity.User;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.slf4j.MDC;

import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import io.jsonwebtoken.JwtException;

import java.io.IOException;

@Component
public class JwtAuthenticationFilter
        extends OncePerRequestFilter {

    private static final Logger log =
            LoggerFactory.getLogger(
                    JwtAuthenticationFilter.class
            );

    private static final String CORRELATION_ID =
            "X-Correlation-ID";

    private final JwtService jwtService;
    private final UserDetailsService userDetailsService;

    public JwtAuthenticationFilter(
            JwtService jwtService,
            UserDetailsService userDetailsService
    ) {
        this.jwtService = jwtService;
        this.userDetailsService = userDetailsService;
    }

    @Override
    protected void doFilterInternal(
            HttpServletRequest request,
            HttpServletResponse response,
            FilterChain filterChain
    ) throws ServletException, IOException {

        String correlationId =
                MDC.get(CORRELATION_ID);

        String authorizationHeader =
                request.getHeader("Authorization");

        String requestUri =
                request.getRequestURI();

        String httpMethod =
                request.getMethod();

        /*
         * Requests without a Bearer token are allowed to
         * continue. Spring Security will determine whether
         * the endpoint requires authentication.
         */
        if (authorizationHeader == null
                || !authorizationHeader.startsWith("Bearer ")) {

            log.debug(
                    "Request without JWT authorization " +
                            "method={} uri={} correlationId={}",
                    httpMethod,
                    requestUri,
                    correlationId
            );

            filterChain.doFilter(request, response);
            return;
        }

        /*
         * Extract the JWT.
         *
         * IMPORTANT:
         * Never log the token itself.
         */
        String token =
                authorizationHeader.substring(7);

        log.debug(
                "JWT authentication attempt method={} uri={} correlationId={}",
                httpMethod,
                requestUri,
                correlationId
        );

        try {

            String username =
                    jwtService.extractUsername(token);

            if (username == null) {

                log.warn(
                        "JWT does not contain a valid username " +
                                "method={} uri={} correlationId={}",
                        httpMethod,
                        requestUri,
                        correlationId
                );

                filterChain.doFilter(
                        request,
                        response
                );

                return;
            }

            /*
             * Only authenticate if Spring Security has not
             * already established an authentication.
             */
            if (SecurityContextHolder
                    .getContext()
                    .getAuthentication() == null) {

                User user =
                        (User) userDetailsService
                                .loadUserByUsername(username);

                if (jwtService.isTokenValid(
                        token,
                        user
                )) {

                    UsernamePasswordAuthenticationToken
                            authentication =
                            new UsernamePasswordAuthenticationToken(
                                    user,
                                    null,
                                    user.getAuthorities()
                            );

                    authentication.setDetails(
                            new WebAuthenticationDetailsSource()
                                    .buildDetails(request)
                    );

                    SecurityContextHolder
                            .getContext()
                            .setAuthentication(
                                    authentication
                            );

                    log.info(
                            "JWT authentication successful " +
                                    "username={} role={} method={} uri={} correlationId={}",
                            user.getUsername(),
                            user.getRole(),
                            httpMethod,
                            requestUri,
                            correlationId
                    );

                } else {

                    log.warn(
                            "JWT validation failed " +
                                    "username={} method={} uri={} correlationId={}",
                            username,
                            httpMethod,
                            requestUri,
                            correlationId
                    );
                }

            } else {

                log.debug(
                        "Security context already authenticated " +
                                "username={} method={} uri={} correlationId={}",
                        username,
                        httpMethod,
                        requestUri,
                        correlationId
                );
            }

        } catch (JwtException ex) {

            /*
             * This includes expired, malformed, unsupported,
             * or otherwise invalid JWTs.
             *
             * Do not log the token.
             */
            log.warn(
                    "Invalid JWT received " +
                            "method={} uri={} correlationId={} reason={}",
                    httpMethod,
                    requestUri,
                    correlationId,
                    ex.getMessage()
            );

        } catch (IllegalArgumentException ex) {

            log.warn(
                    "Invalid JWT argument received " +
                            "method={} uri={} correlationId={} reason={}",
                    httpMethod,
                    requestUri,
                    correlationId,
                    ex.getMessage()
            );

        } catch (Exception ex) {

            /*
             * Unexpected security/filter failure.
             */
            log.error(
                    "Unexpected error during JWT authentication " +
                            "method={} uri={} correlationId={}",
                    httpMethod,
                    requestUri,
                    correlationId,
                    ex
            );
        }

        filterChain.doFilter(
                request,
                response
        );
    }
}