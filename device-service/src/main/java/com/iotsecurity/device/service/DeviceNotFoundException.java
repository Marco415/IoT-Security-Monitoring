package com.iotsecurity.device.service;

public class DeviceNotFoundException extends RuntimeException {

    public DeviceNotFoundException(String deviceId) {
        super("Device not found: " + deviceId);
    }
}