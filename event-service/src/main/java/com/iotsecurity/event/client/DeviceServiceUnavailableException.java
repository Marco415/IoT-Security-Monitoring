package com.iotsecurity.event.client;

public class DeviceServiceUnavailableException
        extends RuntimeException {

    public DeviceServiceUnavailableException(String message) {
        super(message);
    }

    public DeviceServiceUnavailableException(
            String message,
            Throwable cause) {

        super(message, cause);
    }
}