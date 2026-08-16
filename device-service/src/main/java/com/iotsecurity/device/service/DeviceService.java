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

        existingDevice.setName(
                device.getName()
        );

        /*
         * Keep any other fields that your existing
         * Device entity supports here.
         *
         * For example:
         *
         * existingDevice.setType(device.getType());
         * existingDevice.setLocation(device.getLocation());
         * existingDevice.setStatus(device.getStatus());
         */

        Device updatedDevice =
                deviceRepository.save(
                        existingDevice
                );

        log.info(
                "IoT device updated deviceId={}",
                id
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