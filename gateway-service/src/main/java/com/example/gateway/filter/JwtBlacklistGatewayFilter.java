package com.example.gateway.filter;

import com.example.gateway.config.JwtProperties;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.Ordered;
import org.springframework.data.redis.core.ReactiveStringRedisTemplate;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.nio.charset.StandardCharsets;
import java.security.Key;

@Component
public class JwtBlacklistGatewayFilter implements GlobalFilter, Ordered {

    private final ReactiveStringRedisTemplate redisTemplate;
    private final JwtProperties jwtProperties;

    public JwtBlacklistGatewayFilter(ReactiveStringRedisTemplate redisTemplate, JwtProperties jwtProperties) {
        this.redisTemplate = redisTemplate;
        this.jwtProperties = jwtProperties;
    }

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        // 1. Trích xuất Token từ Header "Authorization"
        String authHeader = exchange.getRequest().getHeaders().getFirst(HttpHeaders.AUTHORIZATION);

        if (!StringUtils.hasText(authHeader) || !authHeader.startsWith("Bearer ")) {
            // Không có token -> Để downstream service xử lý hoặc cho phép nếu endpoint public
            return chain.filter(exchange);
        }

        String token = authHeader.substring(7);

        try {
            // 2. Parse JWT (không cần check DB, trích xuất "jti")
            Key key = Keys.hmacShaKeyFor(jwtProperties.getSecret().getBytes(StandardCharsets.UTF_8));
            Claims claims = Jwts.parserBuilder()
                    .setSigningKey(key)
                    .build()
                    .parseClaimsJws(token)
                    .getBody();

            String jti = claims.getId();
            if (!StringUtils.hasText(jti)) {
                return chain.filter(exchange);
            }

            // 3. Truy vấn Reactive Redis kiểm tra blacklist non-blocking
            return redisTemplate.hasKey("blacklist:" + jti)
                    .flatMap(isBlacklisted -> {
                        if (Boolean.TRUE.equals(isBlacklisted)) {
                            // 4. Nếu tồn tại trong Redis: Trả về lỗi 401 Unauthorized ngay lập tức
                            exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
                            return exchange.getResponse().setComplete();
                        }
                        // 5. Nếu không: chuyển tiếp request
                        return chain.filter(exchange);
                    });

        } catch (Exception e) {
            // Token không hợp lệ
            exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
            return exchange.getResponse().setComplete();
        }
    }

    @Override
    public int getOrder() {
        return -1; // Ưu tiên chạy sớm trước khi định tuyến
    }
}
