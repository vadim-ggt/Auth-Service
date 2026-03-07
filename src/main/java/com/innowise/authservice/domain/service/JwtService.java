package com.innowise.authservice.domain.service;

import com.innowise.authservice.domain.entity.Credential;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import jakarta.annotation.PostConstruct;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.security.*;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.*;

@Service
public class JwtService {

    public static final String KEY_ID = "auth-server-key";

    @Value("${jwt.private-key}")
    private String privateKeyString;
    private PrivateKey privateKey;
    private PublicKey publicKey;

    @Value("${application.security.jwt.expiration-minutes:15}")
    private long accessTokenExpirationMinutes;

    @Value("${application.security.jwt.refresh-token.expiration-days:7}")
    private long refreshTokenExpirationDays;


    @PostConstruct
    public void initKeys() {
        try {
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");

            byte[] decodedPrivateKey = Base64.getDecoder().decode(cleanKey(privateKeyString));
            PKCS8EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(decodedPrivateKey);
            this.privateKey = keyFactory.generatePrivate(privateKeySpec);

            if (this.privateKey instanceof RSAPrivateCrtKey crtKey) {
                RSAPublicKeySpec publicKeySpec = new RSAPublicKeySpec(crtKey.getModulus(), crtKey.getPublicExponent());
                this.publicKey = keyFactory.generatePublic(publicKeySpec);
            } else {
                throw new RuntimeException("Приватный ключ не является экземпляром RSAPrivateCrtKey");
            }
        } catch (Exception e) {
            throw new RuntimeException("Ошибка инициализации RSA ключей из переменной окружения", e);
        }
    }

    private String cleanKey(String key) {
        if (key == null) return "";
        return key.replaceAll("\\n", "")
                .replaceAll("\\s", "")
                .replace("-----BEGINPRIVATEKEY-----", "")
                .replace("-----ENDPRIVATEKEY-----", "");
    }


    public Map<String, String> generateTokens(Credential credential) {
           String accessToken = buildAccessToken(credential);
           String refreshToken = buildRefreshToken(credential);

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

    private String buildRefreshToken(Credential credential) {
        Instant now = Instant.now();
        return Jwts.builder()
                .header().keyId(KEY_ID).and()
                .subject(credential.getUserId().toString())
                .claim("scope", credential.getRole().name())
                .claim("email", credential.getEmail())
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

        public boolean isTokenValid(String token) {
            try {
                return !isTokenExpired(token);
            } catch (Exception e) {
                return false;
            }
        }

    public String extractEmail(String token) {
        return extractAllClaims(token).get("email", String.class);
    }

    public String extractRole(String token) {
        return extractAllClaims(token).get("scope", String.class);
    }

    }