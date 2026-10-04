package com.example.identity.controller;

import com.example.identity.dto.LoginRequest;
import com.example.identity.model.User;
import com.example.identity.repository.RefreshTokenRepository;
import com.example.identity.repository.UserRepository;
import com.example.identity.service.JwtUtils;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.http.MediaType;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

import java.util.Set;
import java.util.concurrent.TimeUnit;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
@TestPropertySource(properties = {
        "spring.datasource.url=jdbc:h2:mem:identity_test_db_bai4;DB_CLOSE_DELAY=-1;MODE=PostgreSQL",
        "spring.datasource.driver-class-name=org.h2.Driver",
        "spring.datasource.username=sa",
        "spring.datasource.password=",
        "spring.jpa.database-platform=org.hibernate.dialect.H2Dialect",
        "spring.data.redis.host=localhost",
        "spring.data.redis.port=6379"
})
class LogoutRedisTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private RefreshTokenRepository refreshTokenRepository;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Autowired
    private JwtUtils jwtUtils;

    @Autowired
    private StringRedisTemplate redisTemplate;

    @Autowired
    private ObjectMapper objectMapper;

    @BeforeEach
    void setup() {
        refreshTokenRepository.deleteAll();
        userRepository.deleteAll();

        User user = new User("admin", passwordEncoder.encode("password123"), Set.of("ROLE_ADMIN"));
        userRepository.save(user);
    }

    @Test
    @DisplayName("Bài tập 4: Logout ghi blacklist vào Redis với key blacklist:{jti} và TTL trùng khớp")
    void testLogoutWritesBlacklistToRedis() throws Exception {
        // 1. Đăng nhập để lấy Access Token
        LoginRequest loginRequest = new LoginRequest("admin", "password123");
        MvcResult loginResult = mockMvc.perform(post("/api/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(loginRequest)))
                .andExpect(status().isOk())
                .andReturn();

        JsonNode loginJson = objectMapper.readTree(loginResult.getResponse().getContentAsString());
        String accessToken = loginJson.get("accessToken").asText();
        String jti = jwtUtils.getJtiFromToken(accessToken);

        assertThat(jti).isNotEmpty();

        // 2. Gọi API Logout
        mockMvc.perform(post("/api/auth/logout")
                        .header("Authorization", "Bearer " + accessToken))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.message").value("Logged out successfully and token blacklisted"));

        // 3. Kiểm tra Redis
        String blacklistKey = "blacklist:" + jti;
        String blacklistedValue = redisTemplate.opsForValue().get(blacklistKey);
        assertThat(blacklistedValue).isEqualTo("revoked");

        Long ttlSeconds = redisTemplate.getExpire(blacklistKey, TimeUnit.SECONDS);
        assertThat(ttlSeconds).isNotNull().isGreaterThan(0L);

        // 4. Kiểm tra Refresh token đã được dọn dẹp
        assertThat(refreshTokenRepository.findAll()).isEmpty();

        // Dọn dẹp key sau test
        redisTemplate.delete(blacklistKey);
    }
}
