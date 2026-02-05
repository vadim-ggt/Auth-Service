package com.innowise.authservice.domain.config;

import feign.RequestInterceptor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class FeignClientConfig {

    private final String INTERNAL_HEADER_NAME = "x-internal-key";

    @Value("${internal.api-key}")
    private String internalApiKey;

    @Bean
    public RequestInterceptor feignRequestInterceptor() {
        return requestTemplate -> {
            requestTemplate.header(INTERNAL_HEADER_NAME, internalApiKey);
        };
    }
}
