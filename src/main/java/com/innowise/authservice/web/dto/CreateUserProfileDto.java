package com.innowise.authservice.web.dto;

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
public class CreateUserProfileDto {
    private UUID userId;
    private String name;
    private String surname;
    private String email;
    private LocalDate birthDate;
}