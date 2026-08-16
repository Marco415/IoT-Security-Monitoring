package com.iotsecurity.device.controller;

import com.iotsecurity.device.model.Device;
import com.iotsecurity.device.service.DeviceService;
import jakarta.validation.Valid;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api/devices")
public class DeviceController {

    private final DeviceService deviceService;

    public DeviceController(DeviceService deviceService) {
        this.deviceService = deviceService;
    }

    /**
     * Get all devices.
     *
     * GET /api/devices
     */
    @GetMapping
    public ResponseEntity<List<Device>> getAllDevices() {

        return ResponseEntity.ok(
                deviceService.getAllDevices()
        );
    }

    /**
     * Get a device by its deviceId.
     *
     * GET /api/devices/{deviceId}
     */
    @GetMapping("/{deviceId}")
    public ResponseEntity<Device> getDevice(
            @PathVariable String deviceId
    ) {

        return ResponseEntity.ok(
                deviceService.getDeviceById(deviceId)
        );
    }

    /**
     * Register a new device.
     *
     * POST /api/devices
     */
    @PostMapping
    public ResponseEntity<Device> createDevice(
            @Valid @RequestBody Device device
    ) {

        Device createdDevice =
                deviceService.createDevice(device);

        return ResponseEntity
                .status(HttpStatus.CREATED)
                .body(createdDevice);
    }

    /**
     * Update an existing device.
     *
     * PUT /api/devices/{deviceId}
     */
    @PutMapping("/{deviceId}")
    public ResponseEntity<Device> updateDevice(
            @PathVariable String deviceId,
            @Valid @RequestBody Device device
    ) {

        return ResponseEntity.ok(
                deviceService.updateDevice(
                        deviceId,
                        device
                )
        );
    }

    /**
     * Delete a device.
     *
     * DELETE /api/devices/{deviceId}
     */
    @DeleteMapping("/{deviceId}")
    public ResponseEntity<Void> deleteDevice(
            @PathVariable String deviceId
    ) {

        deviceService.deleteDevice(deviceId);

        return ResponseEntity.noContent().build();
    }
}