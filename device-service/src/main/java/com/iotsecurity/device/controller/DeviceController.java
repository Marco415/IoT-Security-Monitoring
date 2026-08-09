package com.iotsecurity.device.controller;

import com.iotsecurity.device.model.Device;
import com.iotsecurity.device.repository.DeviceRepository;
import jakarta.validation.Valid;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api/devices")
public class DeviceController {

    private final DeviceRepository deviceRepository;

    public DeviceController(DeviceRepository deviceRepository) {
        this.deviceRepository = deviceRepository;
    }


    // GET /api/devices
    @GetMapping
    public List<Device> getAllDevices() {
        return deviceRepository.findAll();
    }


    // GET /api/devices/{id}
    @GetMapping("/{id}")
    public ResponseEntity<Device> getDeviceById(@PathVariable Long id) {

        return deviceRepository.findById(id)
                .map(ResponseEntity::ok)
                .orElse(ResponseEntity.notFound().build());
    }


    // POST /api/devices
    @PostMapping
    public ResponseEntity<Device> createDevice(
            @Valid @RequestBody Device device) {

        Device savedDevice = deviceRepository.save(device);

        return ResponseEntity.ok(savedDevice);
    }


    // PUT /api/devices/{id}
    @PutMapping("/{id}")
    public ResponseEntity<Device> updateDevice(
            @PathVariable Long id,
            @Valid @RequestBody Device device) {

        return deviceRepository.findById(id)
                .map(existingDevice -> {

                    existingDevice.setDeviceId(device.getDeviceId());
                    existingDevice.setName(device.getName());
                    existingDevice.setDeviceType(device.getDeviceType());
                    existingDevice.setManufacturer(device.getManufacturer());
                    existingDevice.setIpAddress(device.getIpAddress());
                    existingDevice.setLocation(device.getLocation());
                    existingDevice.setStatus(device.getStatus());

                    Device updatedDevice =
                            deviceRepository.save(existingDevice);

                    return ResponseEntity.ok(updatedDevice);
                })
                .orElse(ResponseEntity.notFound().build());
    }


    // DELETE /api/devices/{id}
    @DeleteMapping("/{id}")
    public ResponseEntity<Void> deleteDevice(
            @PathVariable Long id) {

        if (!deviceRepository.existsById(id)) {
            return ResponseEntity.notFound().build();
        }

        deviceRepository.deleteById(id);

        return ResponseEntity.noContent().build();
    }
}