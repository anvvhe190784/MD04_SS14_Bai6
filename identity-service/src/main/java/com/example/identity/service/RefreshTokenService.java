package com.example.identity.service;

import com.example.identity.config.JwtProperties;
import com.example.identity.dto.TokenResponse;
import com.example.identity.exception.TokenRefreshException;
import com.example.identity.model.RefreshToken;
import com.example.identity.model.User;
import com.example.identity.repository.RefreshTokenRepository;
import com.example.identity.repository.UserRepository;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.Optional;
import java.util.UUID;

@Service
public class RefreshTokenService {

    private final RefreshTokenRepository refreshTokenRepository;
    private final UserRepository userRepository;
    private final JwtProperties jwtProperties;
    private final JwtUtils jwtUtils;

    public RefreshTokenService(RefreshTokenRepository refreshTokenRepository,
                                UserRepository userRepository,
                                JwtProperties jwtProperties,
                                JwtUtils jwtUtils) {
        this.refreshTokenRepository = refreshTokenRepository;
        this.userRepository = userRepository;
        this.jwtProperties = jwtProperties;
        this.jwtUtils = jwtUtils;
    }

    @Transactional
    public RefreshToken createRefreshToken(Long userId) {
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new IllegalArgumentException("User not found with id: " + userId));

        RefreshToken refreshToken = new RefreshToken();
        refreshToken.setUser(user);
        refreshToken.setToken(UUID.randomUUID().toString());
        refreshToken.setExpiryDate(Instant.now().plusMillis(jwtProperties.getRefreshTokenExpiration()));

        return refreshTokenRepository.save(refreshToken);
    }

    public RefreshToken verifyExpiration(RefreshToken token) {
        if (token.getExpiryDate().compareTo(Instant.now()) < 0) {
            refreshTokenRepository.delete(token);
            throw new TokenRefreshException("Refresh token was expired. Please make a new signin request");
        }
        return token;
    }

    @Transactional
    public TokenResponse refreshToken(String requestToken) {
        // 1. Tìm RefreshToken trong DB bằng chuỗi requestToken
        RefreshToken token = refreshTokenRepository.findByToken(requestToken)
                .orElseThrow(() -> new TokenRefreshException("Refresh token is not in database!"));

        // 2. Nếu token đã hết hạn -> Ném Exception
        verifyExpiration(token);

        User user = token.getUser();

        // 3. (QUAN TRỌNG - Rotation): Xóa bản ghi Refresh Token cũ khỏi DB
        refreshTokenRepository.delete(token);

        // 4. Lấy User từ token cũ, gọi JwtUtils để tạo Access Token mới
        String newAccessToken = jwtUtils.generateAccessToken(user);

        // 5. Gọi hàm createRefreshToken để tạo Refresh Token hoàn toàn mới
        RefreshToken newRefreshToken = createRefreshToken(user.getId());

        // 6. Trả về cặp Token mới cho Client
        return new TokenResponse(newAccessToken, newRefreshToken.getToken());
    }

    public Optional<RefreshToken> findByToken(String token) {
        return refreshTokenRepository.findByToken(token);
    }

    @Transactional
    public void deleteByToken(String token) {
        refreshTokenRepository.deleteByToken(token);
    }

    @Transactional
    public void deleteByUser(User user) {
        refreshTokenRepository.deleteByUser(user);
    }
}
