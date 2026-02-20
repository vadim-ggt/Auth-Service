package com.innowise.authservice.web.client;

import com.innowise.authservice.domain.config.FeignClientConfig;
import com.innowise.authservice.web.dto.CreateUserProfileDto;
import org.springframework.cloud.openfeign.FeignClient;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;

@FeignClient(
        name = "user-service",
        url = "${application.config.user-url}",
        path = "/api/users",
        configuration = FeignClientConfig.class
)
public interface UserClient {

    @PostMapping
    void createUserProfile(@RequestBody CreateUserProfileDto createUserProfileDto);
}
