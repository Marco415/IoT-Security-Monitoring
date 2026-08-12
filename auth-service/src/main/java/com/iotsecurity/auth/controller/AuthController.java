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

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;

import java.time.LocalDateTime;

@RestController
@RequestMapping("/api/auth")
public class AuthController {

    private final UserRepository userRepository;
    private final AuthEventRepository authEventRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtService jwtService;

    public AuthController(
            UserRepository userRepository,
            AuthEventRepository authEventRepository,
            PasswordEncoder passwordEncoder,
            JwtService jwtService
    ) {
        this.userRepository = userRepository;
        this.authEventRepository = authEventRepository;
        this.passwordEncoder = passwordEncoder;
        this.jwtService = jwtService;
    }

    @PostMapping("/login")
    public ResponseEntity<?> login(
            @Valid @RequestBody LoginRequest request,
            HttpServletRequest httpRequest
    ) {

        String username = request.getUsername();

        String sourceIp = getClientIp(httpRequest);

        User user = userRepository
                .findByUsername(username)
                .orElse(null);

        if (user == null) {

            recordAuthenticationEvent(
                    "AUTHENTICATION_FAILURE",
                    username,
                    sourceIp,
                    "FAILURE"
            );

            return ResponseEntity
                    .status(HttpStatus.UNAUTHORIZED)
                    .body("Invalid username or password");
        }

        if (!user.isEnabled()) {

            recordAuthenticationEvent(
                    "AUTHENTICATION_FAILURE",
                    username,
                    sourceIp,
                    "ACCOUNT_DISABLED"
            );

            return ResponseEntity
                    .status(HttpStatus.UNAUTHORIZED)
                    .body("Account is disabled");
        }

        if (!passwordEncoder.matches(
                request.getPassword(),
                user.getPassword()
        )) {

            recordAuthenticationEvent(
                    "AUTHENTICATION_FAILURE",
                    username,
                    sourceIp,
                    "FAILURE"
            );

            return ResponseEntity
                    .status(HttpStatus.UNAUTHORIZED)
                    .body("Invalid username or password");
        }

        String token = jwtService.generateToken(
                user.getUsername(),
                user.getRole()
        );

        recordAuthenticationEvent(
                "AUTHENTICATION_SUCCESS",
                username,
                sourceIp,
                "SUCCESS"
        );

        return ResponseEntity.ok(
                new LoginResponse(token, "Bearer")
        );
    }

    private void recordAuthenticationEvent(
            String eventType,
            String username,
            String sourceIp,
            String result
    ) {

        AuthEvent event = new AuthEvent(
                eventType,
                username,
                sourceIp,
                LocalDateTime.now(),
                result,
                "auth-service"
        );

        authEventRepository.save(event);

        System.out.println(
                eventType +
                        " username=" + username +
                        " sourceIp=" + sourceIp +
                        " timestamp=" + event.getTimestamp() +
                        " result=" + result
        );
    }

    private String getClientIp(HttpServletRequest request) {

        String forwardedFor =
                request.getHeader("X-Forwarded-For");

        if (forwardedFor != null &&
                !forwardedFor.isBlank()) {

            return forwardedFor.split(",")[0].trim();
        }

        String realIp =
                request.getHeader("X-Real-IP");

        if (realIp != null &&
                !realIp.isBlank()) {

            return realIp;
        }

        return request.getRemoteAddr();
    }
}