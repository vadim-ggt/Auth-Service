package com.innowise.authservice.domain.dao;

import com.innowise.authservice.domain.entity.RefreshToken;
import org.springframework.data.repository.CrudRepository;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.UUID;


@Repository
public interface RefreshTokenRepository
        extends CrudRepository<RefreshToken, String> {
    List<RefreshToken> findByUserId(UUID userId);

}