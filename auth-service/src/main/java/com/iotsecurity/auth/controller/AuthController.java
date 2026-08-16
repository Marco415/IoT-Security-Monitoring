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

        try {

            authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(
                            username,
                            request.getPassword()
                    )
            );

            User user = userRepository
                    .findByUsername(username)
                    .orElseThrow();

            String token = jwtService.generateToken(user);

            saveAuthEvent(
                    "LOGIN",
                    username,
                    sourceIp,
                    "SUCCESS"
            );

            return ResponseEntity.ok(
                    new LoginResponse(
                            token,
                            user.getUsername(),
                            user.getRole()
                    )
            );

        } catch (AuthenticationException ex) {

            saveAuthEvent(
                    "LOGIN",
                    username,
                    sourceIp,
                    "FAILURE"
            );

            return ResponseEntity
                    .status(HttpStatus.UNAUTHORIZED)
                    .body("Invalid username or password");
        }
    }

    @PostMapping("/register")
    public ResponseEntity<?> register(
            @Valid @RequestBody LoginRequest request,
            HttpServletRequest httpRequest
    ) {

        String username = request.getUsername().trim();
        String sourceIp = getClientIp(httpRequest);

        if (userRepository.existsByUsername(username)) {

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
                passwordEncoder.encode(request.getPassword()),
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

        return ResponseEntity
                .status(HttpStatus.CREATED)
                .body("User registered successfully");
    }

    @GetMapping("/me")
    public ResponseEntity<?> currentUser() {

        Object principal =
                SecurityContextHolder
                        .getContext()
                        .getAuthentication()
                        .getPrincipal();

        if (!(principal instanceof User user)) {

            return ResponseEntity
                    .status(HttpStatus.UNAUTHORIZED)
                    .body("Not authenticated");
        }

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

        AuthEvent event = new AuthEvent(
                eventType,
                username,
                sourceIp,
                LocalDateTime.now(),
                result,
                "auth-service"
        );

        authEventRepository.save(event);
    }

    private String getClientIp(HttpServletRequest request) {

        String forwardedFor =
                request.getHeader("X-Forwarded-For");

        if (forwardedFor != null
                && !forwardedFor.isBlank()) {

            return forwardedFor.split(",")[0].trim();
        }

        return request.getRemoteAddr();
    }
}