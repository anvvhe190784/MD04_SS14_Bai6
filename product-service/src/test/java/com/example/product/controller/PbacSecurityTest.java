package com.example.product.controller;

import com.example.product.model.Product;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;

import java.math.BigDecimal;
import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.util.Date;
import java.util.List;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
class PbacSecurityTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private ObjectMapper objectMapper;

    @Value("${app.jwt.secret}")
    private String secret;

    private String createTokenWithPermissions(String username, List<String> permissions) {
        Key key = Keys.hmacShaKeyFor(secret.getBytes(StandardCharsets.UTF_8));
        return Jwts.builder()
                .setSubject(username)
                .claim("permissions", permissions)
                .claim("roles", List.of("STAFF"))
                .setIssuedAt(new Date())
                .setExpiration(new Date(System.currentTimeMillis() + 60000))
                .signWith(key, SignatureAlgorithm.HS256)
                .compact();
    }

    @Test
    @DisplayName("Bài tập 6: Token 1 chỉ có quyền PRODUCT_READ -> GET 200 OK, POST 403 Forbidden")
    void testTokenWithOnlyReadPermission() throws Exception {
        String tokenReadOnly = createTokenWithPermissions("staff_john", List.of("PRODUCT_READ"));

        // GET -> 200 OK
        mockMvc.perform(get("/api/products")
                        .header("Authorization", "Bearer " + tokenReadOnly))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$").isArray());

        // POST -> 403 Forbidden
        Product newProduct = new Product(null, "Gaming Mouse", new BigDecimal("50.00"));
        mockMvc.perform(post("/api/products")
                        .header("Authorization", "Bearer " + tokenReadOnly)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(newProduct)))
                .andExpect(status().isForbidden());
    }

    @Test
    @DisplayName("Bài tập 6: Token 2 có cả 2 quyền PRODUCT_READ và PRODUCT_CREATE -> cả GET và POST đều 200 OK / 201 Created")
    void testTokenWithReadAndCreatePermissions() throws Exception {
        String tokenFull = createTokenWithPermissions("staff_alice", List.of("PRODUCT_READ", "PRODUCT_CREATE"));

        // GET -> 200 OK
        mockMvc.perform(get("/api/products")
                        .header("Authorization", "Bearer " + tokenFull))
                .andExpect(status().isOk());

        // POST -> 201 Created
        Product newProduct = new Product(null, "UltraWide Monitor", new BigDecimal("450.00"));
        mockMvc.perform(post("/api/products")
                        .header("Authorization", "Bearer " + tokenFull)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(newProduct)))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.name").value("UltraWide Monitor"));
    }
}
