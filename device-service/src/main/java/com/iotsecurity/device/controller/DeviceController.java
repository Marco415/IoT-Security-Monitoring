package com.iotsecurity.device.controller;

import com.iotsecurity.device.model.Device;
import com.iotsecurity.device.service.DeviceService;
import jakarta.validation.Valid;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api/devices")
public class DeviceController {

    private static final Logger log =
            LoggerFactory.getLogger(
                    DeviceController.class
            );

    private final DeviceService deviceService;

    public DeviceController(
            DeviceService deviceService) {

        this.deviceService = deviceService;
    }

    @GetMapping
    public ResponseEntity<List<Device>> getAllDevices() {

        log.info(
                "Retrieving all IoT devices"
        );

        return ResponseEntity.ok(
                deviceService.getAllDevices()
        );
    }

    @GetMapping("/{id}")
    public ResponseEntity<Device> getDevice(
            @PathVariable Long id) {

        log.info(
                "Retrieving IoT device deviceId={}",
                id
        );

        return ResponseEntity.ok(
                deviceService.getDevice(id)
        );
    }

    @GetMapping("/device-id/{deviceId}")
    public ResponseEntity<Device> getDeviceByDeviceId(
            @PathVariable String deviceId) {

        log.info(
                "Retrieving IoT device deviceId={}",
                deviceId
        );

        return ResponseEntity.ok(
                deviceService.getDeviceByDeviceId(deviceId)
        );
    }

    @PostMapping
    public ResponseEntity<Device> createDevice(
            @Valid @RequestBody Device device) {

        log.info(
                "Creating IoT device deviceName={}",
                device.getName()
        );

        Device createdDevice =
                deviceService.createDevice(device);

        log.info(
                "IoT device created deviceId={} deviceName={}",
                createdDevice.getId(),
                createdDevice.getName()
        );

        return ResponseEntity
                .status(HttpStatus.CREATED)
                .body(createdDevice);
    }

    @PutMapping("/{id}")
    public ResponseEntity<Device> updateDevice(
            @PathVariable Long id,
            @Valid @RequestBody Device device) {

        log.info(
                "Updating IoT device deviceId={}",
                id
        );

        Device updatedDevice =
                deviceService.updateDevice(
                        id,
                        device
                );

        log.info(
                "IoT device updated deviceId={}",
                id
        );

        return ResponseEntity.ok(
                updatedDevice
        );
    }

    @DeleteMapping("/{id}")
    public ResponseEntity<Void> deleteDevice(
            @PathVariable Long id) {

        log.warn(
                "Deleting IoT device deviceId={}",
                id
        );

        deviceService.deleteDevice(id);

        log.info(
                "IoT device deleted deviceId={}",
                id
        );

        return ResponseEntity
                .noContent()
                .build();
    }
}