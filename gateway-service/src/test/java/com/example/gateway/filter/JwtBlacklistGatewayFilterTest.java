package com.example.gateway.filter;

import com.example.gateway.config.JwtProperties;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.data.redis.core.ReactiveStringRedisTemplate;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.mock.http.server.reactive.MockServerHttpRequest;
import org.springframework.mock.web.server.MockServerWebExchange;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.util.Date;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.when;

class JwtBlacklistGatewayFilterTest {

    private ReactiveStringRedisTemplate redisTemplate;
    private JwtProperties jwtProperties;
    private JwtBlacklistGatewayFilter filter;
    private GatewayFilterChain chain;

    private final String secret = "vS6K5vH8N2zB4xR9mQ3pL1wT7yC5vH8N2zB4xR9mQ3pL1wT7yC5vH8N2z";

    @BeforeEach
    void setUp() {
        redisTemplate = Mockito.mock(ReactiveStringRedisTemplate.class);
        jwtProperties = new JwtProperties();
        jwtProperties.setSecret(secret);

        filter = new JwtBlacklistGatewayFilter(redisTemplate, jwtProperties);
        chain = Mockito.mock(GatewayFilterChain.class);
        when(chain.filter(any())).thenReturn(Mono.empty());
    }

    private String generateToken(String jti) {
        Key key = Keys.hmacShaKeyFor(secret.getBytes(StandardCharsets.UTF_8));
        return Jwts.builder()
                .setId(jti)
                .setSubject("testuser")
                .setIssuedAt(new Date())
                .setExpiration(new Date(System.currentTimeMillis() + 60000))
                .signWith(key, SignatureAlgorithm.HS256)
                .compact();
    }

    @Test
    @DisplayName("Bài tập 5: Token hợp lệ không nằm trong Blacklist -> Chuyển tiếp request bình thường")
    void testValidTokenNotBlacklistedProceeds() {
        String jti = UUID.randomUUID().toString();
        String token = generateToken(jti);

        when(redisTemplate.hasKey(eq("blacklist:" + jti))).thenReturn(Mono.just(false));

        MockServerHttpRequest request = MockServerHttpRequest.get("/api/products")
                .header(HttpHeaders.AUTHORIZATION, "Bearer " + token)
                .build();
        MockServerWebExchange exchange = MockServerWebExchange.from(request);

        StepVerifier.create(filter.filter(exchange, chain))
                .verifyComplete();

        Mockito.verify(chain).filter(exchange);
        assertThat(exchange.getResponse().getStatusCode()).isNull();
    }

    @Test
    @DisplayName("Bài tập 5: Token có trong Blacklist Redis -> Gateway chặn ngay với mã 401 Unauthorized")
    void testBlacklistedTokenReturns401Unauthorized() {
        String jti = UUID.randomUUID().toString();
        String token = generateToken(jti);

        // Redis xác nhận token đã bị blacklist
        when(redisTemplate.hasKey(eq("blacklist:" + jti))).thenReturn(Mono.just(true));

        MockServerHttpRequest request = MockServerHttpRequest.get("/api/products")
                .header(HttpHeaders.AUTHORIZATION, "Bearer " + token)
                .build();
        MockServerWebExchange exchange = MockServerWebExchange.from(request);

        StepVerifier.create(filter.filter(exchange, chain))
                .verifyComplete();

        // Không bao giờ gọi chain.filter (không chuyển tiếp vào backend)
        Mockito.verify(chain, Mockito.never()).filter(any());
        assertThat(exchange.getResponse().getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
    }
}
