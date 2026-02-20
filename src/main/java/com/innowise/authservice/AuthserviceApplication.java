package com.innowise.authservice;

import jakarta.annotation.PostConstruct;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

@SpringBootApplication(scanBasePackages = "com.innowise.authservice")
public class AuthserviceApplication {
	public static void main(String[] args) {
		SpringApplication.run(AuthserviceApplication.class, args);
	}

}
