package com.iotsecurity.device.repository;

import com.iotsecurity.device.model.Device;
import org.springframework.data.jpa.repository.JpaRepository;

public interface DeviceRepository extends JpaRepository<Device, Long> {
}