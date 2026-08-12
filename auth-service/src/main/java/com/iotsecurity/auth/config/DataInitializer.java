package com.iotsecurity.auth.config;

import com.iotsecurity.auth.entity.User;
import com.iotsecurity.auth.repository.UserRepository;
import org.springframework.boot.CommandLineRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.time.LocalDateTime;

@Configuration
public class DataInitializer {

    @Bean
    CommandLineRunner initializeUsers(
            UserRepository userRepository,
            PasswordEncoder passwordEncoder
    ) {

        return args -> {

            if (userRepository.findByUsername("admin").isEmpty()) {

                User admin = new User(
                        "admin",
                        passwordEncoder.encode("password"),
                        "ADMIN",
                        true,
                        LocalDateTime.now()
                );

                userRepository.save(admin);
            }

            if (userRepository.findByUsername("operator").isEmpty()) {

                User operator = new User(
                        "operator",
                        passwordEncoder.encode("password"),
                        "OPERATOR",
                        true,
                        LocalDateTime.now()
                );

                userRepository.save(operator);
            }
        };
    }
}