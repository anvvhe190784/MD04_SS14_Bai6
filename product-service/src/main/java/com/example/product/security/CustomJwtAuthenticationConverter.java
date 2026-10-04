package com.example.product.security;

import io.jsonwebtoken.Claims;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

@Component
public class CustomJwtAuthenticationConverter {

    public AbstractAuthenticationToken convert(Claims claims) {
        // 1. Lấy username bằng claims.getSubject() chuẩn type-safe
        String username = claims.getSubject();
        List<SimpleGrantedAuthority> authorities = new ArrayList<>();

        // 2. Lấy List<String> từ claim "permissions" (PBAC)
        Object permissionsObj = claims.get("permissions");
        if (permissionsObj instanceof Collection<?> permissions) {
            for (Object perm : permissions) {
                if (perm != null) {
                    authorities.add(new SimpleGrantedAuthority(perm.toString()));
                }
            }
        }

        // 3. Map cả "roles" (RBAC)
        Object rolesObj = claims.get("roles");
        if (rolesObj instanceof Collection<?> roles) {
            for (Object role : roles) {
                if (role != null) {
                    String roleStr = role.toString();
                    authorities.add(new SimpleGrantedAuthority(roleStr));
                    if (!roleStr.startsWith("ROLE_")) {
                        authorities.add(new SimpleGrantedAuthority("ROLE_" + roleStr));
                    }
                }
            }
        }

        // 4. Trả về UsernamePasswordAuthenticationToken chứa danh sách Authorities này
        return new UsernamePasswordAuthenticationToken(username, null, authorities);
    }
}
