package com.iotsecurity.device.service;

import com.iotsecurity.device.model.Device;
import com.iotsecurity.device.repository.DeviceRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;

@Service
@Transactional
public class DeviceService {

    private static final Logger log =
            LoggerFactory.getLogger(DeviceService.class);

    private final DeviceRepository deviceRepository;

    public DeviceService(
            DeviceRepository deviceRepository) {

        this.deviceRepository = deviceRepository;
    }

    public List<Device> getAllDevices() {

        log.info(
                "Retrieving all IoT devices"
        );

        List<Device> devices =
                deviceRepository.findAll();

        log.info(
                "Retrieved {} IoT devices",
                devices.size()
        );

        return devices;
    }

    public Device getDevice(Long id) {

        log.info(
                "Retrieving IoT device deviceId={}",
                id
        );

        return deviceRepository
                .findById(id)
                .orElseThrow(() -> {

                    log.warn(
                            "IoT device not found deviceId={}",
                            id
                    );

                    return new DeviceNotFoundException(
                            "Device with ID " +
                                    id +
                                    " was not found."
                    );
                });
    }

    public Device getDeviceByDeviceId(String deviceId) {

        log.info(
                "Retrieving IoT device deviceId={}",
                deviceId
        );

        return deviceRepository
                .findByDeviceId(deviceId)
                .orElseThrow(() -> {

                    log.warn(
                            "IoT device not found deviceId={}",
                            deviceId
                    );

                    return new DeviceNotFoundException(
                            "Device with device ID " +
                                    deviceId +
                                    " was not found."
                    );
                });
    }

    public Device createDevice(Device device) {

        log.info(
                "Creating IoT device deviceName={}",
                device.getName()
        );

        Device savedDevice =
                deviceRepository.save(device);

        log.info(
                "IoT device created deviceId={} deviceName={}",
                savedDevice.getId(),
                savedDevice.getName()
        );

        return savedDevice;
    }

    public Device updateDevice(
            Long id,
            Device device) {

        log.info(
                "Updating IoT device deviceId={}",
                id
        );

        Device existingDevice =
                getDevice(id);

        // Update all editable device fields
        existingDevice.setDeviceId(
                device.getDeviceId()
        );

        existingDevice.setName(
                device.getName()
        );

        existingDevice.setDeviceType(
                device.getDeviceType()
        );

        existingDevice.setManufacturer(
                device.getManufacturer()
        );

        existingDevice.setIpAddress(
                device.getIpAddress()
        );

        existingDevice.setLocation(
                device.getLocation()
        );

        existingDevice.setStatus(
                device.getStatus()
        );

        // Do NOT update:
        // existingDevice.setId(...)
        // existingDevice.setCreatedAt(...)
        // existingDevice.setUpdatedAt(...)
        //
        // JPA manages the ID and timestamps.
        // @PreUpdate automatically updates updatedAt.

        Device updatedDevice =
                deviceRepository.save(
                        existingDevice
                );

        log.info(
                "IoT device updated deviceId={} name={} deviceType={} status={}",
                updatedDevice.getId(),
                updatedDevice.getName(),
                updatedDevice.getDeviceType(),
                updatedDevice.getStatus()
        );

        return updatedDevice;
    }

    public void deleteDevice(Long id) {

        log.warn(
                "Deleting IoT device deviceId={}",
                id
        );

        Device device =
                getDevice(id);

        deviceRepository.delete(device);

        log.info(
                "IoT device deleted deviceId={}",
                id
        );
    }
}