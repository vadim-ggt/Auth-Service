package com.innowise.authservice.domain.exception;

import org.springframework.http.HttpStatus;

public class EmailAlreadyTakenException extends BusinessException {
    public EmailAlreadyTakenException(String email) {
        super("Email '" + email + "' is already taken", HttpStatus.CONFLICT);
    }
}