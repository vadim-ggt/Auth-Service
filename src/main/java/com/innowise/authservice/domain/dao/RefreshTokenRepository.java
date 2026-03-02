package com.innowise.authservice.domain.dao;

import com.innowise.authservice.domain.entity.RefreshToken;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

// TODO: For high-load scenarios, migrate Refresh Token storage from RDBMS to an In-Memory store (e.g., Redis)
// to reduce disk I/O and offload the primary database.

@Repository
public interface RefreshTokenRepository extends JpaRepository<RefreshToken, Long> {

    Optional<RefreshToken> findByToken(String token);

    List<RefreshToken> findAllByCredentialUserId(UUID userId);

    List<RefreshToken> findAllByCredentialUserIdAndRevokedFalse(UUID userId);
}