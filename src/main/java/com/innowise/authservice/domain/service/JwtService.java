package com.innowise.authservice.domain.service;

import com.innowise.authservice.domain.entity.Credential;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

    @Service
    public class JwtService {

        public static final String KEY_ID = "auth-server-key";

        private final PrivateKey privateKey;
        private final PublicKey publicKey;

        @Value("${application.security.jwt.expiration-minutes:15}")
        private long accessTokenExpirationMinutes;

        @Value("${application.security.jwt.refresh-token.expiration-days:7}")
        private long refreshTokenExpirationDays;

        public JwtService() {
            try {
                KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
                keyGen.initialize(2048);
                KeyPair pair = keyGen.generateKeyPair();
                this.privateKey = pair.getPrivate();
                this.publicKey = pair.getPublic();
            } catch (Exception e) {
                throw new RuntimeException("Error generating RSA keys", e);
            }
        }

        public Map<String, String> generateTokens(Credential credential) {
            String accessToken = buildAccessToken(credential);
            String refreshToken = buildRefreshToken(credential.getUserId());

            Map<String, String> tokens = new HashMap<>();
            tokens.put("access_token", accessToken);
            tokens.put("refresh_token", refreshToken);
            return tokens;
        }

        private String buildAccessToken(Credential credential) {
            Instant now = Instant.now();
            String scope = credential.getRole().name();

            return Jwts.builder()
                    .header().keyId(KEY_ID).and()
                    .subject(credential.getUserId().toString())
                    .claim("scope", scope)
                    .claim("email", credential.getEmail())
                    .issuedAt(Date.from(now))
                    .expiration(Date.from(now.plus(accessTokenExpirationMinutes, ChronoUnit.MINUTES)))
                    .signWith(privateKey, Jwts.SIG.RS256)
                    .compact();
        }

        private String buildRefreshToken(UUID userId) {
            Instant now = Instant.now();
            return Jwts.builder()
                    .header().keyId(KEY_ID).and()
                    .subject(userId.toString())
                    .issuedAt(Date.from(now))
                    .expiration(Date.from(now.plus(refreshTokenExpirationDays, ChronoUnit.DAYS)))
                    .signWith(privateKey, Jwts.SIG.RS256)
                    .compact();
        }

        public boolean isTokenExpired(String token) {
            try {
                return extractAllClaims(token).getExpiration().before(new Date());
            } catch (Exception e) {
                return true;
            }
        }

        public boolean isTokenValid(String token, Credential userDetails) {
            final String sub = extractSubject(token);
            return (sub.equals(userDetails.getUserId().toString())) && !isTokenExpired(token);
        }

        public String extractSubject(String token) {
            return extractAllClaims(token).getSubject();
        }

        private Claims extractAllClaims(String token) {
            return Jwts.parser()
                    .verifyWith(publicKey)
                    .build()
                    .parseSignedClaims(token)
                    .getPayload();
        }

        public PublicKey getPublicKey() {
            return this.publicKey;
        }
    }