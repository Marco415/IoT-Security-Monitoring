package com.iotsecurity.device.controller;

import com.iotsecurity.device.model.Device;
import com.iotsecurity.device.service.DeviceService;
import jakarta.validation.Valid;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.tags.Tag;

import java.util.List;

@RestController
@RequestMapping("/api/devices")
@Tag(
        name = "Devices",
        description = "Device registration and device management operations"
)
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

    @Operation(
            summary = "Get all devices",
            description = "Returns all registered IoT devices."
    )
    @ApiResponses({
            @ApiResponse(
                    responseCode = "200",
                    description = "Devices retrieved successfully"
            ),
            @ApiResponse(
                    responseCode = "401",
                    description = "Authentication required"
            )
    })
    @SecurityRequirement(name = "bearerAuth")
    @GetMapping
    public ResponseEntity<List<Device>> getAllDevices() {

        log.info(
                "Retrieving all IoT devices"
        );

        return ResponseEntity.ok(
                deviceService.getAllDevices()
        );
    }

    @Operation(
            summary = "Get device by database ID",
            description = "Returns a specific IoT device using its database ID."
    )
    @ApiResponses({
            @ApiResponse(
                    responseCode = "200",
                    description = "Device found"
            ),
            @ApiResponse(
                    responseCode = "404",
                    description = "Device not found"
            )
    })
    @SecurityRequirement(name = "bearerAuth")
    @GetMapping("/{id}")
    public ResponseEntity<Device> getDevice(
            @Parameter(
                    description = "Database ID of the IoT device",
                    example = "1",
                    required = true
            )
            @PathVariable Long id) {

        log.info(
                "Retrieving IoT device deviceId={}",
                id
        );

        return ResponseEntity.ok(
                deviceService.getDevice(id)
        );
    }

    @Operation(
            summary = "Get device by ID",
            description = "Returns a specific IoT device using its device ID."
    )
    @ApiResponses({
            @ApiResponse(
                    responseCode = "200",
                    description = "Device found"
            ),
            @ApiResponse(
                    responseCode = "404",
                    description = "Device not found"
            )
    })
    @SecurityRequirement(name = "bearerAuth")
    @GetMapping("/device-id/{deviceId}")
    public ResponseEntity<Device> getDeviceByDeviceId(
            @Parameter(
                    description = "Unique IoT device identifier",
                    example = "DEV-001",
                    required = true
            )
            @PathVariable String deviceId) {

        log.info(
                "Retrieving IoT device deviceId={}",
                deviceId
        );

        return ResponseEntity.ok(
                deviceService.getDeviceByDeviceId(deviceId)
        );
    }

    @Operation(
            summary = "Register a device",
            description = "Registers a new IoT device."
    )
    @ApiResponses({
            @ApiResponse(
                    responseCode = "201",
                    description = "Device registered successfully"
            ),
            @ApiResponse(
                    responseCode = "400",
                    description = "Invalid device data"
            ),
            @ApiResponse(
                    responseCode = "409",
                    description = "Device already exists"
            )
    })
    @SecurityRequirement(name = "bearerAuth")
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

    @Operation(
            summary = "Update a device",
            description = "Updates an existing IoT device."
    )
    @ApiResponses({
            @ApiResponse(
                    responseCode = "200",
                    description = "Device updated successfully"
            ),
            @ApiResponse(
                    responseCode = "404",
                    description = "Device not found"
            ),
            @ApiResponse(
                    responseCode = "400",
                    description = "Invalid device data"
            )
    })
    @SecurityRequirement(name = "bearerAuth")
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

    @Operation(
            summary = "Delete a device",
            description = "Deletes an existing IoT device."
    )
    @ApiResponses({
            @ApiResponse(
                    responseCode = "204",
                    description = "Device deleted successfully"
            ),
            @ApiResponse(
                    responseCode = "404",
                    description = "Device not found"
            )
    })
    @SecurityRequirement(name = "bearerAuth")
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