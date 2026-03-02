package com.innowise.authservice.domain.dao;

import com.innowise.authservice.domain.entity.Credential;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;
import java.util.UUID;

@Repository
public interface CredentialRepository extends JpaRepository<Credential, Long> {

    Optional<Credential> findByEmail(String email);

    boolean existsByEmail(String email);

    Optional<Credential> findByUserId(UUID userId);
}