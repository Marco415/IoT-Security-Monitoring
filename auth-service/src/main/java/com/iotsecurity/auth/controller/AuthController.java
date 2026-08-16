package com.iotsecurity.auth.controller;

import com.iotsecurity.auth.dto.LoginRequest;
import com.iotsecurity.auth.dto.LoginResponse;
import com.iotsecurity.auth.entity.AuthEvent;
import com.iotsecurity.auth.entity.User;
import com.iotsecurity.auth.repository.AuthEventRepository;
import com.iotsecurity.auth.repository.UserRepository;
import com.iotsecurity.auth.security.JwtService;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.slf4j.MDC;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;

import org.springframework.web.bind.annotation.*;

import java.time.LocalDateTime;

@RestController
@RequestMapping("/api/auth")
public class AuthController {

    private static final Logger log =
            LoggerFactory.getLogger(AuthController.class);

    private static final String CORRELATION_ID =
            "X-Correlation-ID";

    private final AuthenticationManager authenticationManager;
    private final UserRepository userRepository;
    private final AuthEventRepository authEventRepository;
    private final JwtService jwtService;
    private final PasswordEncoder passwordEncoder;

    public AuthController(
            AuthenticationManager authenticationManager,
            UserRepository userRepository,
            AuthEventRepository authEventRepository,
            JwtService jwtService,
            PasswordEncoder passwordEncoder
    ) {
        this.authenticationManager = authenticationManager;
        this.userRepository = userRepository;
        this.authEventRepository = authEventRepository;
        this.jwtService = jwtService;
        this.passwordEncoder = passwordEncoder;
    }

    @PostMapping("/login")
    public ResponseEntity<?> login(
            @Valid @RequestBody LoginRequest request,
            HttpServletRequest httpRequest
    ) {

        String username = request.getUsername().trim();
        String sourceIp = getClientIp(httpRequest);
        String correlationId = MDC.get(CORRELATION_ID);

        log.info(
                "Login attempt username={} sourceIp={} correlationId={}",
                username,
                sourceIp,
                correlationId
        );

        try {

            authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(
                            username,
                            request.getPassword()
                    )
            );

            log.info(
                    "Authentication successful username={} sourceIp={} correlationId={}",
                    username,
                    sourceIp,
                    correlationId
            );

            User user = userRepository
                    .findByUsername(username)
                    .orElseThrow(() ->
                            new IllegalStateException(
                                    "Authenticated user could not be found"
                            )
                    );

            String token =
                    jwtService.generateToken(user);

            saveAuthEvent(
                    "LOGIN",
                    username,
                    sourceIp,
                    "SUCCESS"
            );

            log.info(
                    "Login successful username={} role={} correlationId={}",
                    username,
                    user.getRole(),
                    correlationId
            );

            return ResponseEntity.ok(
                    new LoginResponse(
                            token,
                            user.getUsername(),
                            user.getRole()
                    )
            );

        } catch (AuthenticationException ex) {

            log.warn(
                    "Login authentication failed username={} sourceIp={} correlationId={}",
                    username,
                    sourceIp,
                    correlationId
            );

            saveAuthEvent(
                    "LOGIN",
                    username,
                    sourceIp,
                    "FAILURE"
            );

            return ResponseEntity
                    .status(HttpStatus.UNAUTHORIZED)
                    .body("Invalid username or password");

        } catch (Exception ex) {

            log.error(
                    "Unexpected error during login username={} sourceIp={} correlationId={}",
                    username,
                    sourceIp,
                    correlationId,
                    ex
            );

            return ResponseEntity
                    .status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body("An unexpected error occurred");
        }
    }

    @PostMapping("/register")
    public ResponseEntity<?> register(
            @Valid @RequestBody LoginRequest request,
            HttpServletRequest httpRequest
    ) {

        String username = request.getUsername().trim();
        String sourceIp = getClientIp(httpRequest);
        String correlationId = MDC.get(CORRELATION_ID);

        log.info(
                "Registration attempt username={} sourceIp={} correlationId={}",
                username,
                sourceIp,
                correlationId
        );

        try {

            if (userRepository.existsByUsername(username)) {

                log.warn(
                        "Registration failed because username already exists " +
                                "username={} sourceIp={} correlationId={}",
                        username,
                        sourceIp,
                        correlationId
                );

                saveAuthEvent(
                        "REGISTER",
                        username,
                        sourceIp,
                        "FAILURE"
                );

                return ResponseEntity
                        .status(HttpStatus.CONFLICT)
                        .body("Username already exists");
            }

            User user = new User(
                    username,
                    passwordEncoder.encode(
                            request.getPassword()
                    ),
                    "USER",
                    true
            );

            userRepository.save(user);

            saveAuthEvent(
                    "REGISTER",
                    username,
                    sourceIp,
                    "SUCCESS"
            );

            log.info(
                    "User registered successfully username={} sourceIp={} correlationId={}",
                    username,
                    sourceIp,
                    correlationId
            );

            return ResponseEntity
                    .status(HttpStatus.CREATED)
                    .body("User registered successfully");

        } catch (Exception ex) {

            log.error(
                    "Unexpected error during user registration " +
                            "username={} sourceIp={} correlationId={}",
                    username,
                    sourceIp,
                    correlationId,
                    ex
            );

            return ResponseEntity
                    .status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body("An unexpected error occurred");
        }
    }

    @GetMapping("/me")
    public ResponseEntity<?> currentUser() {

        String correlationId =
                MDC.get(CORRELATION_ID);

        log.debug(
                "Current user request received correlationId={}",
                correlationId
        );

        Object principal =
                SecurityContextHolder
                        .getContext()
                        .getAuthentication()
                        .getPrincipal();

        if (!(principal instanceof User user)) {

            log.warn(
                    "Unauthenticated request to /api/auth/me " +
                            "correlationId={}",
                    correlationId
            );

            return ResponseEntity
                    .status(HttpStatus.UNAUTHORIZED)
                    .body("Not authenticated");
        }

        log.info(
                "Current user retrieved username={} role={} correlationId={}",
                user.getUsername(),
                user.getRole(),
                correlationId
        );

        return ResponseEntity.ok(
                new LoginResponse(
                        "",
                        user.getUsername(),
                        user.getRole()
                )
        );
    }

    private void saveAuthEvent(
            String eventType,
            String username,
            String sourceIp,
            String result
    ) {

        String correlationId =
                MDC.get(CORRELATION_ID);

        AuthEvent event = new AuthEvent(
                eventType,
                username,
                sourceIp,
                LocalDateTime.now(),
                result,
                "auth-service"
        );

        authEventRepository.save(event);

        log.info(
                "Authentication event saved " +
                        "eventType={} username={} sourceIp={} result={} correlationId={}",
                eventType,
                username,
                sourceIp,
                result,
                correlationId
        );
    }

    private String getClientIp(
            HttpServletRequest request) {

        String forwardedFor =
                request.getHeader("X-Forwarded-For");

        if (forwardedFor != null
                && !forwardedFor.isBlank()) {

            return forwardedFor
                    .split(",")[0]
                    .trim();
        }

        return request.getRemoteAddr();
    }
}