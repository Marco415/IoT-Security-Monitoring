package com.iotsecurity.auth.security;

import com.iotsecurity.auth.repository.UserRepository;

import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

@Service
public class CustomUserDetailsService implements UserDetailsService {

    private final UserRepository userRepository;

    public CustomUserDetailsService(
            UserRepository userRepository
    ) {
        this.userRepository = userRepository;
    }

    @Override
    public org.springframework.security.core.userdetails.UserDetails loadUserByUsername(
            String username
    ) throws UsernameNotFoundException {

        return userRepository.findByUsername(username)
                .orElseThrow(
                        () -> new UsernameNotFoundException(
                                "User not found: " + username
                        )
                );
    }
}