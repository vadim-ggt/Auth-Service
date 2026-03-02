package com.innowise.authservice.web.dto.auth;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDate;
import java.util.UUID;

@Data
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class RegisterRequest {
    private UUID userId;
    private String email;
    private String password;
    private String name;
    private String surname;
    private LocalDate birthDate;
}
