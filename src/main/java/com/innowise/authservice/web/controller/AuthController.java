package com.innowise.authservice.web.controller;

import com.innowise.authservice.domain.entity.Role;
import com.innowise.authservice.domain.service.AuthService;
import com.innowise.authservice.web.dto.RefreshTokenRequest;
import com.innowise.authservice.web.dto.auth.AuthenticationRequest;
import com.innowise.authservice.web.dto.auth.AuthenticationResponse;
import com.innowise.authservice.web.dto.auth.RegisterRequest;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.util.Map;
import java.util.UUID;

@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
public class AuthController {
    private final AuthService authService;

    @PostMapping("/register")
    public ResponseEntity<AuthenticationResponse> register(@RequestBody RegisterRequest request) {
        return ResponseEntity.ok(authService.register(request));
    }

    @PostMapping("/login")
    public ResponseEntity<AuthenticationResponse> login(@RequestBody AuthenticationRequest request) {
        return ResponseEntity.ok(authService.login(request));
    }

    @PostMapping("/refresh")
    public ResponseEntity<AuthenticationResponse> refresh(@RequestBody RefreshTokenRequest request) {
        return ResponseEntity.ok(authService.refreshToken(request));
    }

    @GetMapping("/validate")
    public ResponseEntity<String> validateToken(@RequestParam String token) {
        authService.validateToken(token);
        return ResponseEntity.ok("Token is valid");
    }

    @GetMapping("/.well-known/jwks.json")
    public ResponseEntity<Map<String, Object>> getJwtSet() {
        return ResponseEntity.ok(authService.getJwkSet());
    }

    @DeleteMapping("/internal/user/{userId}")
    public ResponseEntity<Void> rollbackUser(@PathVariable UUID userId) {
        authService.deleteUserByUserId(userId);
        return new ResponseEntity<>(HttpStatus.NO_CONTENT);
    }

    @PutMapping("/internal/users/{userId}/role")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<Void> updateRole(@PathVariable UUID userId, @RequestParam Role role) {
        authService.updateUserRole(userId, role);
        return ResponseEntity.noContent().build();
    }
}
