package com.iotsecurity.soc;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.cloud.client.discovery.EnableDiscoveryClient;

@SpringBootApplication
@EnableDiscoveryClient
public class SocServiceApplication {

	public static void main(String[] args) {
		SpringApplication.run(SocServiceApplication.class, args);
	}
}