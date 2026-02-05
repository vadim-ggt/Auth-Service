package com.innowise.authservice.domain.config;


import org.springframework.cloud.openfeign.EnableFeignClients;
import org.springframework.context.annotation.Configuration;

@Configuration
@EnableFeignClients(basePackages = "com.innowise.authservice.web.client")
public class FeignConfig {
}