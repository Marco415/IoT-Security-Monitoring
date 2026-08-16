package com.iotsecurity.auth.config;

import com.iotsecurity.auth.entity.User;
import com.iotsecurity.auth.repository.UserRepository;

import org.springframework.boot.CommandLineRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import org.springframework.security.crypto.password.PasswordEncoder;

@Configuration
public class DataInitializer {

    @Bean
    CommandLineRunner initializeUsers(
            UserRepository userRepository,
            PasswordEncoder passwordEncoder
    ) {

        return args -> {

            if (!userRepository.existsByUsername("admin")) {

                User admin = new User(
                        "admin",
                        passwordEncoder.encode("admin123"),
                        "ADMIN",
                        true
                );

                userRepository.save(admin);
            }
        };
    }
}