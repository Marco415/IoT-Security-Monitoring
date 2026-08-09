package com.iotsecurity.device.model;

import jakarta.persistence.*;
import jakarta.validation.constraints.NotBlank;

import java.time.LocalDateTime;

@Entity
@Table(name = "devices")
public class Device {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @NotBlank
    @Column(nullable = false, unique = true)
    private String deviceId;

    @NotBlank
    @Column(nullable = false)
    private String name;

    @NotBlank
    @Column(nullable = false)
    private String deviceType;

    private String manufacturer;

    private String ipAddress;

    private String location;

    @Column(nullable = false)
    private String status;

    @Column(nullable = false, updatable = false)
    private LocalDateTime createdAt;

    @Column(nullable = false)
    private LocalDateTime updatedAt;


    // Default constructor
    public Device() {
    }


    // Automatically set timestamps when creating a device
    @PrePersist
    protected void onCreate() {
        createdAt = LocalDateTime.now();
        updatedAt = LocalDateTime.now();
    }


    // Automatically update updatedAt when modifying a device
    @PreUpdate
    protected void onUpdate() {
        updatedAt = LocalDateTime.now();
    }


    // Getter for id
    public Long getId() {
        return id;
    }

    // Setter for id
    public void setId(Long id) {
        this.id = id;
    }


    // Getter for deviceId
    public String getDeviceId() {
        return deviceId;
    }

    // Setter for deviceId
    public void setDeviceId(String deviceId) {
        this.deviceId = deviceId;
    }


    // Getter for name
    public String getName() {
        return name;
    }

    // Setter for name
    public void setName(String name) {
        this.name = name;
    }


    // Getter for deviceType
    public String getDeviceType() {
        return deviceType;
    }

    // Setter for deviceType
    public void setDeviceType(String deviceType) {
        this.deviceType = deviceType;
    }


    // Getter for manufacturer
    public String getManufacturer() {
        return manufacturer;
    }

    // Setter for manufacturer
    public void setManufacturer(String manufacturer) {
        this.manufacturer = manufacturer;
    }


    // Getter for ipAddress
    public String getIpAddress() {
        return ipAddress;
    }

    // Setter for ipAddress
    public void setIpAddress(String ipAddress) {
        this.ipAddress = ipAddress;
    }


    // Getter for location
    public String getLocation() {
        return location;
    }

    // Setter for location
    public void setLocation(String location) {
        this.location = location;
    }


    // Getter for status
    public String getStatus() {
        return status;
    }

    // Setter for status
    public void setStatus(String status) {
        this.status = status;
    }


    // Getter for createdAt
    public LocalDateTime getCreatedAt() {
        return createdAt;
    }

    // Setter for createdAt
    public void setCreatedAt(LocalDateTime createdAt) {
        this.createdAt = createdAt;
    }


    // Getter for updatedAt
    public LocalDateTime getUpdatedAt() {
        return updatedAt;
    }

    // Setter for updatedAt
    public void setUpdatedAt(LocalDateTime updatedAt) {
        this.updatedAt = updatedAt;
    }
}