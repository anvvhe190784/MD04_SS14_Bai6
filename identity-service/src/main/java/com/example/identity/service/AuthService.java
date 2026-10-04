package com.example.identity.service;

import com.example.identity.repository.UserRepository;
import io.jsonwebtoken.Claims;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.stereotype.Service;

import java.util.Date;
import java.util.concurrent.TimeUnit;

@Service
public class AuthService {

    private final JwtUtils jwtUtils;
    private final StringRedisTemplate redisTemplate;
    private final RefreshTokenService refreshTokenService;
    private final UserRepository userRepository;

    public AuthService(JwtUtils jwtUtils,
                       StringRedisTemplate redisTemplate,
                       RefreshTokenService refreshTokenService,
                       UserRepository userRepository) {
        this.jwtUtils = jwtUtils;
        this.redisTemplate = redisTemplate;
        this.refreshTokenService = refreshTokenService;
        this.userRepository = userRepository;
    }

    public void logout(String token) {
        if (token != null && token.startsWith("Bearer ")) {
            token = token.substring(7);
        }

        Claims claims = jwtUtils.getAllClaimsFromToken(token);
        String jti = claims.getId();
        Date expiration = claims.getExpiration();
        long nowMillis = System.currentTimeMillis();
        long ttlMillis = expiration.getTime() - nowMillis;

        // Lưu key "blacklist:{jti}" vào Redis với giá trị "revoked" và TTL = exp - now
        if (ttlMillis > 0 && jti != null) {
            String key = "blacklist:" + jti;
            redisTemplate.opsForValue().set(key, "revoked", ttlMillis, TimeUnit.MILLISECONDS);
        }

        // Xóa luôn Refresh Token của user tương ứng
        String username = claims.getSubject();
        if (username != null) {
            userRepository.findByUsername(username).ifPresent(refreshTokenService::deleteByUser);
        }
    }
}
