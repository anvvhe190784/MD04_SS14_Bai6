package com.example.identity.controller;

import com.example.identity.dto.LoginRequest;
import com.example.identity.dto.RefreshRequest;
import com.example.identity.model.User;
import com.example.identity.repository.RefreshTokenRepository;
import com.example.identity.repository.UserRepository;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
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

import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
@TestPropertySource(properties = {
        "spring.datasource.url=jdbc:h2:mem:identity_test_db_bai3;DB_CLOSE_DELAY=-1;MODE=PostgreSQL",
        "spring.datasource.driver-class-name=org.h2.Driver",
        "spring.datasource.username=sa",
        "spring.datasource.password=",
        "spring.jpa.database-platform=org.hibernate.dialect.H2Dialect"
})
class TokenRotationTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private RefreshTokenRepository refreshTokenRepository;

    @Autowired
    private PasswordEncoder passwordEncoder;

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
    @DisplayName("Bài tập 3: Token Rotation - Cấp token mới và hủy token cũ, tái sử dụng bị chặn 403 Forbidden")
    void testTokenRotationFlow() throws Exception {
        // Bước 1: Login để lấy cặp Token A (Access) và R1 (Refresh)
        LoginRequest loginRequest = new LoginRequest("admin", "password123");
        MvcResult loginResult = mockMvc.perform(post("/api/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(loginRequest)))
                .andExpect(status().isOk())
                .andReturn();

        JsonNode loginJson = objectMapper.readTree(loginResult.getResponse().getContentAsString());
        String tokenA = loginJson.get("accessToken").asText();
        String r1 = loginJson.get("refreshToken").asText();

        assertThat(tokenA).isNotEmpty();
        assertThat(r1).isNotEmpty();

        // Bước 2: Gửi R1 vào API /refresh -> Nhận cặp Token mới B (Access) và R2 (Refresh)
        RefreshRequest refreshRequest1 = new RefreshRequest(r1);
        MvcResult refreshResult = mockMvc.perform(post("/api/auth/refresh")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(refreshRequest1)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.accessToken").isNotEmpty())
                .andExpect(jsonPath("$.refreshToken").isNotEmpty())
                .andReturn();

        JsonNode refreshJson = objectMapper.readTree(refreshResult.getResponse().getContentAsString());
        String tokenB = refreshJson.get("accessToken").asText();
        String r2 = refreshJson.get("refreshToken").asText();

        assertThat(tokenB).isNotEqualTo(tokenA);
        assertThat(r2).isNotEqualTo(r1);

        // Bước 3: Gửi lại R1 vào API /refresh lần nữa -> Mong đợi 403 Forbidden
        mockMvc.perform(post("/api/auth/refresh")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(refreshRequest1)))
                .andExpect(status().isForbidden());

        // Bước 4: Gửi R2 vào API /refresh -> Thành công nhận cặp token mới C và R3
        RefreshRequest refreshRequest2 = new RefreshRequest(r2);
        mockMvc.perform(post("/api/auth/refresh")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(refreshRequest2)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.accessToken").isNotEmpty())
                .andExpect(jsonPath("$.refreshToken").isNotEmpty());
    }
}
