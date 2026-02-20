package com.innowise.authservice.domain.service;

import com.innowise.authservice.domain.dao.CredentialRepository;
import com.innowise.authservice.domain.dao.RefreshTokenRepository;
import com.innowise.authservice.domain.entity.Credential;
import com.innowise.authservice.domain.entity.RefreshToken;
import com.innowise.authservice.domain.entity.Role;
import com.innowise.authservice.domain.exception.EmailAlreadyTakenException;
import com.innowise.authservice.domain.exception.TokenRefreshException;
import com.innowise.authservice.web.client.UserClient;
import com.innowise.authservice.web.dto.CreateUserProfileDto;
import com.innowise.authservice.web.dto.RefreshTokenRequest;
import com.innowise.authservice.web.dto.auth.AuthenticationRequest;
import com.innowise.authservice.web.dto.auth.AuthenticationResponse;
import com.innowise.authservice.web.dto.auth.RegisterRequest;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.security.interfaces.RSAPublicKey;
import java.time.LocalDateTime;
import java.util.Map;
import java.util.UUID;


@Service
@RequiredArgsConstructor
public class AuthService {

    private final CredentialRepository credentialRepository;
    private final RefreshTokenRepository refreshTokenRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtService jwtService;
    private final AuthenticationManager authenticationManager;
    private final UserClient userClient;

    @Transactional
    public AuthenticationResponse register(RegisterRequest request) {
        if (credentialRepository.existsByEmail(request.getEmail())) {
            throw new EmailAlreadyTakenException(request.getEmail());
        }

        UUID newUserId = UUID.randomUUID();

        Credential credential = Credential.builder()
                .userId(newUserId)
                .email(request.getEmail())
                .password(passwordEncoder.encode(request.getPassword()))
                .role(Role.ROLE_USER)
                .enabled(true)
                .build();

        Credential savedUser = credentialRepository.save(credential);

        CreateUserProfileDto createUserProfileDto = CreateUserProfileDto.builder()
                        .userId(newUserId)
                        .email(request.getEmail())
                        .name(request.getName())
                        .surname(request.getSurname())
                        .birthDate(request.getBirthDate())
                        .build();

        request.setUserId(newUserId);
        try {
            userClient.createUserProfile(createUserProfileDto);
        } catch (Exception e) {
            throw new RuntimeException("Failed to create user profile. Service unavailable.", e);
        }

        return generateAuthResponse(savedUser);
    }

    @Transactional
    public AuthenticationResponse login(AuthenticationRequest request) {
        authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                        request.getEmail(),
                        request.getPassword()
                )
        );

        Credential user = credentialRepository.findByEmail(request.getEmail())
                .orElseThrow(() -> new UsernameNotFoundException("User not found"));

        return generateAuthResponse(user);
    }

    @Transactional
    public AuthenticationResponse refreshToken(RefreshTokenRequest request) {
        String tokenStr = request.getRefreshToken();

        if (!jwtService.isTokenValid(tokenStr)) {
            throw new TokenRefreshException("Refresh token is invalid");
        }

        RefreshToken storedToken = refreshTokenRepository.findByToken(tokenStr)
                .orElseThrow(() -> new TokenRefreshException("Token not found in database"));

        if (storedToken.isRevoked() || storedToken.getExpiresAt().isBefore(LocalDateTime.now())) {
            throw new TokenRefreshException("Refresh token is revoked or expired");
        }

        storedToken.setRevoked(true);
        refreshTokenRepository.save(storedToken);

        return generateAuthResponse(storedToken.getCredential());
    }


    public Map<String, Object> getJwkSet() {
        RSAKey rsaKey = new RSAKey.Builder((RSAPublicKey) jwtService.getPublicKey())
                .keyID(JwtService.KEY_ID)
                .build();
        return new JWKSet(rsaKey).toJSONObject();
    }

    @Transactional
    public void deleteUserByUserId(UUID userId) {
        Credential user = credentialRepository.findByUserId(userId)
                .orElseThrow(() -> new RuntimeException("User not found"));
        credentialRepository.delete(user);
    }

    public void validateToken(String token) {
        if (!jwtService.isTokenValid(token)) {
            throw new RuntimeException("Token is invalid");
        }
    }

    private AuthenticationResponse generateAuthResponse(Credential user) {
        Map<String, String> tokens = jwtService.generateTokens(user);
        String accessToken = tokens.get("access_token");
        String refreshToken = tokens.get("refresh_token");

        saveUserRefreshToken(user, refreshToken);

        return AuthenticationResponse.builder()
                .accessToken(accessToken)
                .refreshToken(refreshToken)
                .build();
    }

    private void saveUserRefreshToken(Credential user, String token) {
        RefreshToken refreshToken = RefreshToken.builder()
                .credential(user)
                .token(token)
                .revoked(false)
                .expiresAt(LocalDateTime.now().plusDays(7))
                .build();
        refreshTokenRepository.save(refreshToken);
    }
}
