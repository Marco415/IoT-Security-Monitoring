package com.iotsecurity.device.service;

import com.iotsecurity.device.model.Device;
import com.iotsecurity.device.repository.DeviceRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;

@Service
@Transactional
public class DeviceService {

    private static final Logger logger =
            LoggerFactory.getLogger(DeviceService.class);

    private final DeviceRepository deviceRepository;

    public DeviceService(DeviceRepository deviceRepository) {
        this.deviceRepository = deviceRepository;
    }

    /**
     * Get all registered devices.
     */
    @Transactional(readOnly = true)
    public List<Device> getAllDevices() {

        logger.info("DEVICE_LIST retrieving all devices");

        return deviceRepository.findAll();
    }

    /**
     * Get a device using its IoT device identifier.
     */
    @Transactional(readOnly = true)
    public Device getDeviceById(String deviceId) {

        logger.info(
                "DEVICE_LOOKUP deviceId={}",
                deviceId
        );

        return deviceRepository.findByDeviceId(deviceId)
                .orElseThrow(() ->
                        new DeviceNotFoundException(deviceId));
    }

    /**
     * Register a new device.
     */
    public Device createDevice(Device device) {

        logger.info(
                "DEVICE_CREATE deviceId={}",
                device.getDeviceId()
        );

        if (deviceRepository.existsByDeviceId(device.getDeviceId())) {
            throw new DataIntegrityViolationException(
                    "A device with deviceId '" +
                            device.getDeviceId() +
                            "' already exists"
            );
        }

        return deviceRepository.save(device);
    }

    /**
     * Update an existing device.
     */
    public Device updateDevice(
            String deviceId,
            Device updatedDevice
    ) {

        logger.info(
                "DEVICE_UPDATE deviceId={}",
                deviceId
        );

        Device existingDevice = getDeviceById(deviceId);

        existingDevice.setName(updatedDevice.getName());
        existingDevice.setDeviceType(updatedDevice.getDeviceType());
        existingDevice.setManufacturer(updatedDevice.getManufacturer());
        existingDevice.setIpAddress(updatedDevice.getIpAddress());
        existingDevice.setLocation(updatedDevice.getLocation());
        existingDevice.setStatus(updatedDevice.getStatus());

        return deviceRepository.save(existingDevice);
    }

    /**
     * Delete a device.
     */
    public void deleteDevice(String deviceId) {

        logger.info(
                "DEVICE_DELETE deviceId={}",
                deviceId
        );

        Device device = getDeviceById(deviceId);

        deviceRepository.delete(device);
    }
}