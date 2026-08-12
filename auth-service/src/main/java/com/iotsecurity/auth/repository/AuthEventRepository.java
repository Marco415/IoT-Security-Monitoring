package com.iotsecurity.auth.repository;

import com.iotsecurity.auth.entity.AuthEvent;
import org.springframework.data.jpa.repository.JpaRepository;

public interface AuthEventRepository extends JpaRepository<AuthEvent, Long> {
}