package com.innowise.authservice.domain.exception;

import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ResponseStatus;

@ResponseStatus(HttpStatus.SERVICE_UNAVAILABLE)
public class UserServiceCrashedException extends RuntimeException {

    public UserServiceCrashedException(String message) {
        super(message);
    }

    public UserServiceCrashedException(String message, Throwable cause) {
        super(message, cause);
    }
}
