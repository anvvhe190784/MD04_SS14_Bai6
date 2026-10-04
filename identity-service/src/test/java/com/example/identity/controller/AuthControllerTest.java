package com.example.identity.controller;

import com.example.identity.dto.LoginRequest;
import com.example.identity.model.RefreshToken;
import com.example.identity.model.User;
import com.example.identity.repository.RefreshTokenRepository;
import com.example.identity.repository.UserRepository;
import com.example.identity.service.JwtUtils;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.jsonwebtoken.Claims;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

import java.time.Instant;
import java.util.Optional;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
@TestPropertySource(properties = {
        "spring.datasource.url=jdbc:h2:mem:identity_test_db;DB_CLOSE_DELAY=-1;MODE=PostgreSQL",
        "spring.datasource.driver-class-name=org.h2.Driver",
        "spring.datasource.username=sa",
        "spring.datasource.password=",
        "spring.jpa.database-platform=org.hibernate.dialect.H2Dialect"
})
class AuthControllerTest {

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
    private ObjectMapper objectMapper;

    @BeforeEach
    void setup() {
        refreshTokenRepository.deleteAll();
        userRepository.deleteAll();

        User user = new User("admin", passwordEncoder.encode("password123"), Set.of("ROLE_ADMIN"));
        userRepository.save(user);
    }

    @Test
    @DisplayName("Bài tập 1: Login thành công cấp phát Access Token (JWT) và Refresh Token (UUID lưu DB)")
    void testLoginIssuesAccessTokenAndRefreshToken() throws Exception {
        LoginRequest loginRequest = new LoginRequest("admin", "password123");

        MvcResult result = mockMvc.perform(post("/api/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(loginRequest)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.accessToken").isNotEmpty())
                .andExpect(jsonPath("$.refreshToken").isNotEmpty())
                .andExpect(jsonPath("$.tokenType").value("Bearer"))
                .andReturn();

        String responseBody = result.getResponse().getContentAsString();
        JsonNode jsonNode = objectMapper.readTree(responseBody);
        String accessToken = jsonNode.get("accessToken").asText();
        String refreshTokenString = jsonNode.get("refreshToken").asText();

        // 1. Kiểm tra Access Token claims
        assertThat(jwtUtils.validateToken(accessToken)).isTrue();
        Claims claims = jwtUtils.getAllClaimsFromToken(accessToken);
        assertThat(claims.getSubject()).isEqualTo("admin");
        assertThat(claims.get("roles")).isNotNull();
        assertThat(claims.getExpiration()).isAfter(claims.getIssuedAt());

        // 2. Kiểm tra Refresh Token lưu trong DB
        Optional<RefreshToken> storedToken = refreshTokenRepository.findByToken(refreshTokenString);
        assertThat(storedToken).isPresent();
        assertThat(storedToken.get().getUser().getUsername()).isEqualTo("admin");
        assertThat(storedToken.get().getExpiryDate()).isAfter(Instant.now());
    }

    @Test
    @DisplayName("Bài tập 1: Login thất bại khi sai mật khẩu trả về 401 Unauthorized")
    void testLoginFailsWithWrongPassword() throws Exception {
        LoginRequest loginRequest = new LoginRequest("admin", "wrongpass");

        mockMvc.perform(post("/api/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(loginRequest)))
                .andExpect(status().isUnauthorized());
    }
}
