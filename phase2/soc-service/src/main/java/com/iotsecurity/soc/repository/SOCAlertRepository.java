package com.iotsecurity.soc.repository;

import com.iotsecurity.soc.model.SOCAlert;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.UUID;

public interface SOCAlertRepository extends JpaRepository<SOCAlert, UUID> {
}